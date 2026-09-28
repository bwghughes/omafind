//! Background reverse-DNS lookups with an in-memory cache.

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;

const WORKERS: usize = 4;

pub struct Resolver {
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    pending: HashSet<IpAddr>,
    tx: Sender<IpAddr>,
}

impl Resolver {
    pub fn new() -> Self {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = channel::<IpAddr>();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..WORKERS {
            let rx: Arc<Mutex<Receiver<IpAddr>>> = rx.clone();
            let cache = cache.clone();
            thread::spawn(move || {
                loop {
                    let Ok(ip) = rx.lock().unwrap().recv() else { return };
                    let name = reverse_lookup(ip);
                    cache.lock().unwrap().insert(ip, name);
                }
            });
        }
        Resolver { cache, pending: HashSet::new(), tx }
    }

    /// Cached hostname for `ip`, queueing a lookup the first time it is seen.
    pub fn lookup(&mut self, ip: IpAddr) -> Option<String> {
        if let Some(hit) = self.cache.lock().unwrap().get(&ip) {
            return hit.clone();
        }
        if self.pending.insert(ip) {
            let _ = self.tx.send(ip);
        }
        None
    }

    pub fn is_pending(&self, ip: IpAddr) -> bool {
        !self.cache.lock().unwrap().contains_key(&ip)
    }
}

fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let mut host = [0 as libc::c_char; 1025];
    // SAFETY: the sockaddr structs are fully initialised and outlive the call;
    // `host` is a writable buffer of the size we pass.
    let rc = unsafe {
        match ip {
            IpAddr::V4(a) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(a.octets());
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(a) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = a.octets();
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo NUL-terminates `host` on success.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) }.to_string_lossy().into_owned();
    (!name.is_empty()).then_some(name)
}
