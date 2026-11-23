use std::net::{SocketAddr, SocketAddrV4};

/// A single bound ephemeral IPv4 socket. Never resolve a hostname or a port range.
pub fn endpoint(value: &str) -> Option<SocketAddr> {
    let addr: SocketAddrV4 = value.parse().ok()?;
    (addr.ip().is_private() && addr.port() >= 1024 && !matches!(addr.ip().octets()[3], 0 | 255))
        .then_some(SocketAddr::V4(addr))
}
