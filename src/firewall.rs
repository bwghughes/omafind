//! Blocking via nftables.
//!
//! Denied apps are matched by the cgroup v2 scope systemd puts each launched
//! app into (`socket cgroupv2`), so the rules follow the app's processes
//! rather than its binary path. Writing nftables needs root, so the daemon
//! calls `sudo -n /usr/local/bin/omafind firewall apply <scopes...>`; the
//! sudoers entry installed by install.sh allows exactly that command.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const HELPER: &str = "/usr/local/bin/omafind";
const NFT: &str = "/usr/bin/nft";
const TABLE: &str = "omafind";
const RETRY: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Idle,
    Active,
    Unavailable(String),
}

impl Status {
    pub fn label(&self) -> String {
        match self {
            Status::Idle => "idle".into(),
            Status::Active => "active".into(),
            Status::Unavailable(why) => format!("unavailable: {why}"),
        }
    }
}

pub struct Firewall {
    applied: Option<BTreeSet<String>>,
    failed_at: Option<Instant>,
    pub status: Status,
}

impl Firewall {
    pub fn new() -> Self {
        Firewall { applied: None, failed_at: None, status: Status::Idle }
    }

    /// Make the kernel's block list match `scopes`, calling out to the
    /// privileged helper only when something changed.
    pub fn sync(&mut self, scopes: &BTreeSet<String>) {
        if self.applied.as_ref() == Some(scopes) {
            return;
        }
        // Nothing to block and no helper that could have blocked anything
        // earlier. With the helper installed, the first sync always runs so
        // rules left over from a previous session get cleared.
        if self.applied.is_none() && scopes.is_empty() && fs::metadata(HELPER).is_err() {
            self.applied = Some(BTreeSet::new());
            return;
        }
        if self.failed_at.is_some_and(|t| t.elapsed() < RETRY) && self.applied.is_none() {
            return;
        }
        match run_helper(scopes) {
            Ok(()) => {
                self.applied = Some(scopes.clone());
                self.failed_at = None;
                self.status = if scopes.is_empty() { Status::Idle } else { Status::Active };
            }
            Err(why) => {
                self.applied = None;
                self.failed_at = Some(Instant::now());
                self.status = Status::Unavailable(why);
            }
        }
    }
}

fn run_helper(scopes: &BTreeSet<String>) -> Result<(), String> {
    if fs::metadata(HELPER).is_err() {
        return Err(format!("{HELPER} not installed (run install.sh)"));
    }
    let out = Command::new("sudo")
        .arg("-n")
        .arg(HELPER)
        .args(["firewall", "apply"])
        .args(scopes)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("sudo: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if err.contains("password is required") || err.contains("a terminal is required") {
        return Err("sudoers rule missing (run install.sh)".into());
    }
    Err(err.lines().last().unwrap_or("helper failed").to_string())
}

// ----- privileged side ---------------------------------------------------

fn invoking_uid() -> Result<u32, String> {
    std::env::var("SUDO_UID")
        .or_else(|_| std::env::var("PKEXEC_UID"))
        .map_err(|_| "run through sudo or pkexec".to_string())?
        .parse()
        .map_err(|_| "bad invoking uid".to_string())
}

/// Only the invoking user's own app scopes may be targeted.
fn validate_scope(path: &str, uid: u32) -> Result<(), String> {
    let prefix = format!("user.slice/user-{uid}.slice/user@{uid}.service/app.slice/");
    let scope = path.strip_prefix(&prefix).ok_or_else(|| format!("refusing {path}: not one of your app scopes"))?;
    let valid_chars = scope.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c));
    if scope.is_empty() || !scope.starts_with("app-") || !valid_chars || scope.contains("..") {
        return Err(format!("refusing {path}: unexpected scope name"));
    }
    if !fs::metadata(format!("/sys/fs/cgroup/{path}")).is_ok_and(|m| m.is_dir()) {
        return Err(format!("refusing {path}: no such cgroup"));
    }
    Ok(())
}

pub fn ruleset(scopes: &[String]) -> String {
    let mut s = format!("table inet {TABLE}\ndelete table inet {TABLE}\n");
    if scopes.is_empty() {
        return s;
    }
    s += &format!("table inet {TABLE} {{\n  chain output {{\n    type filter hook output priority filter; policy accept;\n");
    for path in scopes {
        let level = path.split('/').count();
        s += &format!("    socket cgroupv2 level {level} \"{path}\" counter reject\n");
    }
    s += "  }\n}\n";
    s
}

pub fn helper_main(args: &[String]) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("firewall commands must run as root (the daemon uses sudo -n)".into());
    }
    let uid = invoking_uid()?;
    let scopes: Vec<String> = match args.first().map(String::as_str) {
        Some("apply") => {
            // Scopes can vanish between the daemon's scan and now; skip those
            // instead of failing the whole transaction.
            args[1..]
                .iter()
                .filter(|p| match validate_scope(p, uid) {
                    Ok(()) => true,
                    Err(e) if e.ends_with("no such cgroup") => false,
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(2);
                    }
                })
                .cloned()
                .collect()
        }
        Some("clear") => Vec::new(),
        _ => return Err("usage: omafind firewall apply <scope>... | clear".into()),
    };
    let mut child = Command::new(NFT)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{NFT}: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ruleset(&scopes).as_bytes())
        .map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("nft rejected the ruleset".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_levels() {
        let rs = ruleset(&["user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope".into()]);
        assert!(rs.contains("socket cgroupv2 level 5 \"user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\""));
        assert!(ruleset(&[]).ends_with("delete table inet omafind\n"));
    }

    #[test]
    fn scope_validation() {
        assert!(validate_scope("user.slice/user-1000.slice/user@1000.service/app.slice/../../x", 1000).is_err());
        assert!(validate_scope("system.slice/sshd.service", 1000).is_err());
        assert!(validate_scope("user.slice/user-1000.slice/user@1000.service/app.slice/app-a\"b.scope", 1000).is_err());
    }
}
