//! Parsing of the kernel socket tables in /proc/net.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Socket {
    pub proto: Proto,
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

const TCP_TIME_WAIT: u8 = 0x06;
const TCP_CLOSE: u8 = 0x07;
const TCP_LISTEN: u8 = 0x0A;

impl Socket {
    pub fn is_listening(&self) -> bool {
        self.proto == Proto::Tcp && self.state == TCP_LISTEN
    }

    /// A socket that talks to a real remote peer and is owned by a process.
    pub fn is_remote_connection(&self) -> bool {
        if self.inode == 0 || self.remote.0.is_unspecified() || self.remote.0.is_loopback() {
            return false;
        }
        match self.proto {
            Proto::Tcp => !matches!(self.state, TCP_TIME_WAIT | TCP_CLOSE | TCP_LISTEN),
            Proto::Udp => true,
        }
    }
}

pub fn read_sockets() -> Vec<Socket> {
    let mut out = Vec::new();
    for (path, proto) in [
        ("/proc/net/tcp", Proto::Tcp),
        ("/proc/net/tcp6", Proto::Tcp),
        ("/proc/net/udp", Proto::Udp),
        ("/proc/net/udp6", Proto::Udp),
    ] {
        if let Ok(text) = fs::read_to_string(path) {
            parse_table(&text, proto, &mut out);
        }
    }
    out
}

fn parse_table(text: &str, proto: Proto, out: &mut Vec<Socket>) {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_addr(f[1]), parse_addr(f[2])) else {
            continue;
        };
        let (Ok(state), Ok(uid), Ok(inode)) =
            (u8::from_str_radix(f[3], 16), f[7].parse(), f[9].parse())
        else {
            continue;
        };
        out.push(Socket { proto, local, remote, state, uid, inode });
    }
}

/// Addresses are printed as the raw in-memory words in host byte order.
fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.to_ne_bytes())),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
            }
            Ipv6Addr::from(bytes).to_canonical()
        }
        _ => return None,
    };
    Some((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_ipv4_and_ipv6() {
        assert_eq!(
            parse_addr("0100007F:0277"),
            Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 631))
        );
        // ::ffff:10.0.0.1 is canonicalised to plain IPv4.
        assert_eq!(
            parse_addr("0000000000000000FFFF00000100000A:01BB"),
            Some((IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443))
        );
        assert_eq!(
            parse_addr("00000000000000000000000001000000:0016"),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 22))
        );
    }
}
