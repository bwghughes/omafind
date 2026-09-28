mod dns;
mod firewall;
mod monitor;
mod net;
mod procs;
mod store;

use monitor::{Monitor, Snapshot};
use std::io::{self, Write};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const USAGE: &str = "\
omafind - see which apps talk to the network, and stop the ones you don't like

usage:
  omafind watch [--interval MS]   stream JSON snapshots, one per line, on change
  omafind list [--json]           show current connections once
  omafind deny <app>...           block an app's network access
  omafind allow <app>...          unblock an app and mark it reviewed
  omafind review <app>... | --all mark apps as reviewed (clears the NEW flag)
  omafind notify on|off           toggle first-connection notifications
  omafind rules                   print the rules file
  omafind firewall apply|clear    privileged helper, called by the daemon via sudo
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let result = match cmd {
        "watch" => watch(rest),
        "list" => list(rest.iter().any(|a| a == "--json")),
        "deny" | "allow" | "review" => edit(cmd, rest),
        "notify" => match rest.first().map(String::as_str) {
            Some("on") => store::edit_rules(|r| r.notify_new_apps = true).map(|_| ()).map_err(|e| e.to_string()),
            Some("off") => store::edit_rules(|r| r.notify_new_apps = false).map(|_| ()).map_err(|e| e.to_string()),
            _ => Err("usage: omafind notify on|off".into()),
        },
        "rules" => store::load::<store::Rules>(&store::rules_path())
            .map(|r| println!("{}", serde_json::to_string_pretty(&r).unwrap()))
            .map_err(|e| e.to_string()),
        "firewall" => firewall::helper_main(rest),
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("omafind: {e}");
            ExitCode::FAILURE
        }
    }
}

fn watch(args: &[String]) -> Result<(), String> {
    let mut interval = 1000u64;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--interval" => {
                interval = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|v| *v >= 100)
                    .ok_or("--interval needs a number of milliseconds >= 100")?
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }

    // Exit with whoever started us (the Omarchy shell), even when there is
    // nothing new to write and so no broken pipe to notice.
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    let mut monitor = Monitor::new(false);
    let mut last: Option<Snapshot> = None;
    let stdout = io::stdout();
    loop {
        let snap = monitor.tick();
        if last.as_ref() != Some(&snap) {
            let line = serde_json::to_string(&snap).unwrap();
            let mut out = stdout.lock();
            if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
                break;
            }
            last = Some(snap);
        }
        // SAFETY: as above.
        if unsafe { libc::getppid() } != parent {
            break;
        }
        thread::sleep(Duration::from_millis(interval));
    }
    monitor.flush_seen(true);
    Ok(())
}

fn list(json: bool) -> Result<(), String> {
    let mut monitor = Monitor::new(true);
    monitor.tick();
    // Give reverse DNS a moment so names show up instead of bare IPs.
    thread::sleep(Duration::from_millis(1200));
    let snap = monitor.tick();
    if json {
        println!("{}", serde_json::to_string_pretty(&snap).unwrap());
        return Ok(());
    }
    println!(
        "{} connections from {} apps · firewall {}",
        snap.connections, snap.active_apps, snap.firewall
    );
    for app in &snap.apps {
        let mut tags = Vec::new();
        if app.new {
            tags.push("NEW");
        }
        if app.system {
            tags.push("system");
        }
        if app.blocked {
            tags.push("BLOCKED");
        } else if app.unblockable {
            tags.push("DENIED, not isolated");
        } else if app.denied {
            tags.push("DENIED");
        }
        let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
        println!("\n{} ({}){}", app.name, app.connections, tags);
        for h in &app.hosts {
            let dir = if h.inbound { "←" } else { "→" };
            let times = if h.count > 1 { format!(" ×{}", h.count) } else { String::new() };
            println!("  {dir} {}:{} {}{times}", h.host, h.port, h.proto);
        }
    }
    Ok(())
}

fn edit(cmd: &str, apps: &[String]) -> Result<(), String> {
    if apps.is_empty() {
        return Err(format!("usage: omafind {cmd} <app>..."));
    }
    let all = cmd == "review" && apps.iter().any(|a| a == "--all");
    let seen: Vec<String> = if all {
        store::load::<store::Seen>(&store::seen_path())
            .map_err(|e| e.to_string())?
            .apps
            .into_keys()
            .collect()
    } else {
        Vec::new()
    };
    store::edit_rules(|r| {
        for app in apps.iter().filter(|a| *a != "--all").chain(&seen) {
            match cmd {
                "deny" => {
                    r.deny.insert(app.clone());
                }
                "allow" => {
                    r.deny.remove(app);
                }
                _ => {}
            }
            r.reviewed.insert(app.clone());
        }
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}
