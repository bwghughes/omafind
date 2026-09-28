//! User rules (~/.config/omafind/rules.json, edited by the CLI and by hand)
//! and daemon state (~/.local/state/omafind/seen.json, written by the daemon).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Rules {
    /// Apps whose network access is blocked.
    #[serde(default)]
    pub deny: BTreeSet<String>,
    /// Apps the user has looked at; everything else is flagged as new.
    #[serde(default)]
    pub reviewed: BTreeSet<String>,
    /// Pop a notification the first time an app connects anywhere.
    #[serde(default = "yes")]
    pub notify_new_apps: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Rules { deny: BTreeSet::new(), reviewed: BTreeSet::new(), notify_new_apps: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeenApp {
    pub first_seen: u64,
    pub last_seen: u64,
    /// Most recent remote endpoints ("host:port/proto"), newest last.
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Seen {
    #[serde(default)]
    pub apps: BTreeMap<String, SeenApp>,
}

pub const MAX_HOSTS: usize = 40;

impl Seen {
    /// Record a remote endpoint; returns true if it was not already known.
    pub fn touch(&mut self, app: &str, endpoint: &str, now: u64) -> bool {
        let entry = self.apps.entry(app.to_string()).or_insert_with(|| SeenApp {
            first_seen: now,
            ..Default::default()
        });
        entry.last_seen = now;
        if let Some(pos) = entry.hosts.iter().position(|h| h == endpoint) {
            if pos + 1 != entry.hosts.len() {
                let h = entry.hosts.remove(pos);
                entry.hosts.push(h);
            }
            return false;
        }
        entry.hosts.push(endpoint.to_string());
        if entry.hosts.len() > MAX_HOSTS {
            entry.hosts.remove(0);
        }
        true
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/".into())
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(fallback))
}

pub fn rules_path() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join("omafind/rules.json")
}

pub fn seen_path() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("omafind/seen.json")
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

pub fn load<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> io::Result<T> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e),
    }
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, serde_json::to_string_pretty(value)? + "\n")?;
    fs::rename(tmp, path)
}

/// Read-modify-write of the rules file.
pub fn edit_rules(f: impl FnOnce(&mut Rules)) -> io::Result<Rules> {
    let path = rules_path();
    let mut rules: Rules = load(&path)?;
    f(&mut rules);
    save(&path, &rules)?;
    Ok(rules)
}
