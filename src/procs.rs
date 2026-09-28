//! Mapping sockets to processes, and processes to human "apps".

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Proc {
    pub pid: u32,
    pub app: String,
    pub exe: String,
    /// cgroup v2 path without the leading slash.
    pub cgroup: String,
}

/// Remembers which process owns each socket inode so the (comparatively
/// expensive) walk over every /proc/<pid>/fd only happens when new sockets
/// show up.
#[derive(Default)]
pub struct Owners {
    owner: HashMap<u64, u32>,
    unowned: HashSet<u64>,
    procs: HashMap<u32, Proc>,
}

impl Owners {
    pub fn resolve(&mut self, inodes: &HashSet<u64>) {
        let needs_scan = inodes
            .iter()
            .any(|i| !self.unowned.contains(i) && !self.owner.get(i).is_some_and(|p| pid_alive(*p)));
        if needs_scan {
            self.owner = scan_socket_owners();
            self.unowned = inodes.iter().filter(|i| !self.owner.contains_key(i)).copied().collect();
        }
        self.owner.retain(|i, _| inodes.contains(i));
        self.unowned.retain(|i| inodes.contains(i));
        let live: HashSet<u32> = self.owner.values().copied().collect();
        self.procs.retain(|pid, _| live.contains(pid));
    }

    pub fn owner_of(&mut self, inode: u64) -> Option<&Proc> {
        let pid = *self.owner.get(&inode)?;
        if let std::collections::hash_map::Entry::Vacant(e) = self.procs.entry(pid) {
            e.insert(describe(pid)?);
        }
        self.procs.get(&pid)
    }
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn pids() -> impl Iterator<Item = u32> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
}

fn scan_socket_owners() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    for pid in pids() {
        // Other users' fds are unreadable without root; those sockets end up
        // attributed to their uid instead.
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else { continue };
            let target = target.to_string_lossy();
            if let Some(inode) = target.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inode.parse() {
                    map.entry(inode).or_insert(pid);
                }
        }
    }
    map
}

pub fn describe(pid: u32) -> Option<Proc> {
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string())
        .unwrap_or_default();
    let app = app_name(pid, 0)?;
    Some(Proc { pid, app, exe, cgroup: cgroup_of(pid).unwrap_or_default() })
}

pub fn cgroup_of(pid: u32) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim_start_matches('/').to_string())
}

const INTERPRETERS: &[&str] =
    &["python", "node", "bun", "deno", "ruby", "perl", "java", "bash", "sh", "zsh", "fish", "electron"];

fn is_interpreter(name: &str) -> bool {
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&stem)
}

fn cmdline(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 4, after the parenthesised comm (which may contain spaces).
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Pick a stable, user-recognisable name for the app that owns `pid`.
fn app_name(pid: u32, depth: u8) -> Option<String> {
    let args = cmdline(pid);

    // Chromium/Electron helpers (network service, renderers, ...) belong to
    // the browser that spawned them.
    if depth < 6 && args.iter().any(|a| a.starts_with("--type="))
        && let Some(parent) = ppid(pid).filter(|p| *p > 1)
            && let Some(name) = app_name(parent, depth + 1) {
                return Some(name);
            }

    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?.trim().to_string();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| basename(&p.to_string_lossy()).trim_end_matches(" (deleted)").to_string())
        .unwrap_or_default();

    if (is_interpreter(&exe) || is_interpreter(&comm))
        && let Some(script) = args.iter().skip(1).find(|a| !a.starts_with('-')) {
            let script = script.trim_end_matches('/');
            let name = if script.ends_with(".asar") || script.ends_with("/app") {
                // electron /usr/lib/<app>/app.asar
                script.rsplit('/').nth(1).unwrap_or(script)
            } else {
                basename(script)
            };
            let name = name.trim_end_matches(".py").trim_end_matches(".js").trim_end_matches(".mjs");
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }

    // Versioned installs (e.g. ~/.local/share/foo/versions/1.2.3) have
    // meaningless exe names; comm is usually the real program name.
    if exe.is_empty() || exe.starts_with(|c: char| c.is_ascii_digit()) {
        return Some(comm);
    }
    Some(exe)
}

/// Every process of the current user's app scopes, used to find denied apps
/// even before they manage to open a socket.
pub fn user_app_scopes(uid: u32) -> Vec<(String, Vec<u32>)> {
    let rel = format!("user.slice/user-{uid}.slice/user@{uid}.service/app.slice");
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(format!("/sys/fs/cgroup/{rel}")) else { return out };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !entry.path().is_dir() {
            continue;
        }
        let pids: Vec<u32> = fs::read_to_string(entry.path().join("cgroup.procs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        if !pids.is_empty() {
            out.push((format!("{rel}/{name}"), pids));
        }
    }
    out
}

pub fn app_of(pid: u32) -> Option<String> {
    app_name(pid, 0)
}

/// A scope can be firewalled on its own only if it is an app-*.scope that
/// clearly belongs to `app`, so blocking e.g. `curl` never takes down the
/// terminal it was started from.
pub fn scope_isolates(cgroup: &str, app: &str, uid: u32) -> bool {
    let prefix = format!("user.slice/user-{uid}.slice/user@{uid}.service/app.slice/");
    let Some(scope) = cgroup.strip_prefix(&prefix) else { return false };
    if scope.contains('/') || !scope.starts_with("app-") || !(scope.ends_with(".scope") || scope.ends_with(".service")) {
        return false;
    }
    let scope = scope.to_lowercase();
    let app = app.to_lowercase();
    scope
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
        .any(|part| part == app || part.strip_suffix(".desktop").is_some_and(|p| p.rsplit('.').next() == Some(app.as_str())))
}

pub fn username(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|l| {
                let mut f = l.split(':');
                let name = f.next()?;
                (f.nth(1)?.parse::<u32>().ok()? == uid).then(|| name.to_string())
            })
        })
        .unwrap_or_else(|| format!("uid {uid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation() {
        let base = "user.slice/user-1000.slice/user@1000.service/app.slice/";
        assert!(scope_isolates(&format!("{base}app-Hyprland-firefox-1234.scope"), "firefox", 1000));
        assert!(scope_isolates(&format!("{base}app-hyprland-org.mozilla.firefox.desktop@ab.service"), "firefox", 1000));
        assert!(!scope_isolates(&format!("{base}app-ghostty-surface-transient-3448.scope"), "curl", 1000));
        assert!(!scope_isolates("user.slice/user-1000.slice/session-2.scope", "firefox", 1000));
        assert!(!scope_isolates(&format!("{base}app-firefox-1.scope"), "firefox", 1001));
    }

    #[test]
    fn interpreters() {
        assert!(is_interpreter("python3.12"));
        assert!(is_interpreter("electron34"));
        assert!(!is_interpreter("firefox"));
    }
}
