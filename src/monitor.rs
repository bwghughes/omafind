//! The polling loop: sockets -> apps -> snapshot, plus alerts and blocking.

use crate::dns::Resolver;
use crate::firewall::{self, Firewall};
use crate::net::{self, Proto};
use crate::procs::{self, Owners};
use crate::store::{self, Rules, Seen};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

#[derive(Serialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub proto: &'static str,
    pub inbound: bool,
    pub count: usize,
}

#[derive(Serialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct App {
    pub name: String,
    pub exe: String,
    /// Sockets owned by other users (root, system daemons) that we can only
    /// attribute to a uid.
    pub system: bool,
    pub connections: usize,
    pub hosts: Vec<Host>,
    /// Endpoints seen earlier that are not open right now, newest first.
    pub recent: Vec<String>,
    pub pids: Vec<u32>,
    pub denied: bool,
    /// Denied and the firewall is actively blocking at least one scope.
    pub blocked: bool,
    /// Denied, running, but not in a scope of its own, so it can't be blocked
    /// without collateral damage.
    pub unblockable: bool,
    pub new: bool,
    pub first_seen: u64,
}

#[derive(Serialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub apps: Vec<App>,
    pub connections: usize,
    pub active_apps: usize,
    pub new_apps: usize,
    pub firewall: String,
    pub notify_new_apps: bool,
}

pub struct Monitor {
    uid: u32,
    passive: bool,
    first_run: bool,
    rules: Rules,
    rules_mtime: Option<SystemTime>,
    seen: Seen,
    seen_dirty: bool,
    seen_saved: Instant,
    owners: Owners,
    resolver: Resolver,
    firewall: Firewall,
    pid_apps: HashMap<u32, String>,
    usernames: HashMap<u32, String>,
}

struct Agg {
    exe: String,
    system: bool,
    pids: BTreeSet<u32>,
    hosts: BTreeMap<(IpAddr, u16, Proto, bool), usize>,
}

impl Monitor {
    /// `passive` monitors (one-shot `list`) never notify, block, or write state.
    pub fn new(passive: bool) -> Self {
        let seen_path = store::seen_path();
        let first_run = !seen_path.exists();
        let seen = store::load(&seen_path).unwrap_or_else(|e| {
            eprintln!("omafind: ignoring unreadable {}: {e}", seen_path.display());
            Seen::default()
        });
        Monitor {
            // SAFETY: getuid has no preconditions.
            uid: unsafe { libc::getuid() },
            passive,
            first_run,
            rules: Rules::default(),
            rules_mtime: None,
            seen,
            seen_dirty: false,
            seen_saved: Instant::now(),
            owners: Owners::default(),
            resolver: Resolver::new(),
            firewall: Firewall::new(),
            pid_apps: HashMap::new(),
            usernames: HashMap::new(),
        }
    }

    fn reload_rules(&mut self) {
        let path = store::rules_path();
        let mtime = store::mtime(&path);
        if mtime.is_some() && mtime == self.rules_mtime {
            return;
        }
        self.rules_mtime = mtime;
        match store::load(&path) {
            Ok(rules) => self.rules = rules,
            Err(e) => eprintln!("omafind: keeping previous rules, {}: {e}", path.display()),
        }
    }

    fn username(&mut self, uid: u32) -> String {
        self.usernames.entry(uid).or_insert_with(|| procs::username(uid)).clone()
    }

    pub fn tick(&mut self) -> Snapshot {
        self.reload_rules();
        let now = store::now();

        let sockets = net::read_sockets();
        let listening: HashSet<u16> = sockets.iter().filter(|s| s.is_listening()).map(|s| s.local.1).collect();
        let conns: Vec<_> = sockets.into_iter().filter(|s| s.is_remote_connection()).collect();
        self.owners.resolve(&conns.iter().map(|s| s.inode).collect());

        let mut apps: BTreeMap<String, Agg> = BTreeMap::new();
        let mut unscoped_denied: HashSet<String> = HashSet::new();
        for s in &conns {
            let (name, exe, system, pid) = match self.owners.owner_of(s.inode) {
                Some(p) => {
                    if self.rules.deny.contains(&p.app) && !procs::scope_isolates(&p.cgroup, &p.app, self.uid) {
                        unscoped_denied.insert(p.app.clone());
                    }
                    (p.app.clone(), p.exe.clone(), false, Some(p.pid))
                }
                None => (self.username(s.uid), String::new(), true, None),
            };
            let agg = apps.entry(name).or_insert_with(|| Agg {
                exe,
                system,
                pids: BTreeSet::new(),
                hosts: BTreeMap::new(),
            });
            agg.pids.extend(pid);
            let inbound = s.proto == Proto::Tcp && listening.contains(&s.local.1);
            *agg.hosts.entry((s.remote.0, s.remote.1, s.proto, inbound)).or_default() += 1;
        }

        let blocked_scopes = self.denied_scopes(&mut unscoped_denied);
        if !self.passive {
            self.firewall.sync(&blocked_scopes.values().flatten().cloned().collect());
        }

        let mut out = Vec::new();
        for (name, agg) in &apps {
            let mut hosts = Vec::new();
            let mut new_endpoint = None;
            for (&(ip, port, proto, inbound), &count) in &agg.hosts {
                let resolved = self.resolver.lookup(ip);
                let host = resolved.clone().unwrap_or_else(|| ip.to_string());
                if !self.resolver.is_pending(ip) {
                    let endpoint = format!("{host}:{port}/{}", proto.as_str());
                    let known_app = self.seen.apps.contains_key(name);
                    if !self.passive && self.seen.touch(name, &endpoint, now) {
                        self.seen_dirty = true;
                        if !known_app && new_endpoint.is_none() {
                            new_endpoint = Some(endpoint);
                        }
                    }
                }
                hosts.push(Host { host, ip: ip.to_string(), port, proto: proto.as_str(), inbound, count });
            }
            hosts.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.host.cmp(&b.host)));

            if let Some(endpoint) = new_endpoint
                && !self.first_run && !agg.system && self.rules.notify_new_apps && !self.rules.reviewed.contains(name) {
                    notify_new_app(name, &endpoint);
                }
            out.push(self.app_view(name, Some(agg), hosts, &blocked_scopes, &unscoped_denied));
        }
        // Keep denied apps visible so they can be allowed again.
        for name in self.rules.deny.clone() {
            if !apps.contains_key(&name) {
                out.push(self.app_view(&name, None, Vec::new(), &blocked_scopes, &unscoped_denied));
            }
        }
        out.sort_by(|a, b| {
            (b.new && b.connections > 0)
                .cmp(&(a.new && a.connections > 0))
                .then(b.connections.cmp(&a.connections))
                .then_with(|| a.name.cmp(&b.name))
        });

        self.first_run = false;
        self.flush_seen(false);

        Snapshot {
            connections: out.iter().map(|a| a.connections).sum(),
            active_apps: out.iter().filter(|a| a.connections > 0).count(),
            new_apps: out.iter().filter(|a| a.new && a.connections > 0).count(),
            firewall: if self.rules.deny.is_empty() && self.firewall.status != firewall::Status::Active {
                "idle".into()
            } else {
                self.firewall.status.label()
            },
            notify_new_apps: self.rules.notify_new_apps,
            apps: out,
        }
    }

    fn app_view(
        &self,
        name: &str,
        agg: Option<&Agg>,
        hosts: Vec<Host>,
        blocked_scopes: &HashMap<String, Vec<String>>,
        unscoped_denied: &HashSet<String>,
    ) -> App {
        let seen = self.seen.apps.get(name);
        let open: HashSet<String> = hosts.iter().map(|h| format!("{}:{}/{}", h.host, h.port, h.proto)).collect();
        let recent = seen
            .map(|s| s.hosts.iter().rev().filter(|h| !open.contains(*h)).take(8).cloned().collect())
            .unwrap_or_default();
        let system = agg.is_some_and(|a| a.system);
        let denied = self.rules.deny.contains(name);
        App {
            name: name.to_string(),
            exe: agg.map(|a| a.exe.clone()).unwrap_or_default(),
            system,
            connections: hosts.iter().map(|h| h.count).sum(),
            hosts,
            recent,
            pids: agg.map(|a| a.pids.iter().copied().collect()).unwrap_or_default(),
            denied,
            blocked: denied
                && self.firewall.status == firewall::Status::Active
                && blocked_scopes.get(name).is_some_and(|s| !s.is_empty()),
            unblockable: denied && unscoped_denied.contains(name),
            new: !system && !self.rules.reviewed.contains(name),
            first_seen: seen.map(|s| s.first_seen).unwrap_or(0),
        }
    }

    /// Scopes to firewall, per denied app. Apps found running outside a scope
    /// of their own are added to `unscoped`.
    fn denied_scopes(&mut self, unscoped: &mut HashSet<String>) -> HashMap<String, Vec<String>> {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        if self.rules.deny.is_empty() {
            self.pid_apps.clear();
            return out;
        }
        let mut live = HashSet::new();
        for (scope, pids) in procs::user_app_scopes(self.uid) {
            for pid in pids {
                live.insert(pid);
                let app = match self.pid_apps.get(&pid) {
                    Some(a) => a.clone(),
                    None => {
                        let Some(a) = procs::app_of(pid) else { continue };
                        self.pid_apps.insert(pid, a.clone());
                        a
                    }
                };
                if !self.rules.deny.contains(&app) {
                    continue;
                }
                if procs::scope_isolates(&scope, &app, self.uid) {
                    let scopes = out.entry(app).or_default();
                    if !scopes.contains(&scope) {
                        scopes.push(scope.clone());
                    }
                } else {
                    unscoped.insert(app);
                }
            }
        }
        self.pid_apps.retain(|pid, _| live.contains(pid));
        out
    }

    pub fn flush_seen(&mut self, force: bool) {
        if self.passive || !self.seen_dirty || (!force && self.seen_saved.elapsed() < Duration::from_secs(15)) {
            return;
        }
        if let Err(e) = store::save(&store::seen_path(), &self.seen) {
            eprintln!("omafind: saving seen apps: {e}");
        }
        self.seen_dirty = false;
        self.seen_saved = Instant::now();
    }
}

/// Little Snitch style prompt. Runs on its own thread because `--wait`
/// blocks until the notification is acted on or dismissed.
fn notify_new_app(app: &str, endpoint: &str) {
    let app = app.to_string();
    let body = format!("First connection → {endpoint}");
    thread::spawn(move || {
        let out = Command::new("notify-send")
            .args(["--app-name=omafind", "--icon=network-wired", "--urgency=normal"])
            .args(["--action=allow=Allow", "--action=block=Block", "--wait"])
            .arg(format!("{app} is connecting"))
            .arg(body)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        let Ok(out) = out else { return };
        let choice = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let result = match choice.as_str() {
            "block" => store::edit_rules(|r| {
                r.deny.insert(app.clone());
                r.reviewed.insert(app.clone());
            }),
            "allow" => store::edit_rules(|r| {
                r.deny.remove(&app);
                r.reviewed.insert(app.clone());
            }),
            _ => return,
        };
        if let Err(e) = result {
            eprintln!("omafind: updating rules: {e}");
        }
    });
}
