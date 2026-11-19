use crate::ResultType;
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use webrtc::{peer_connection::RTCPeerConnection, stats::StatsReportType};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        FreeMibTable, GetBestInterfaceEx, GetIfEntry2, GetUnicastIpAddressTable, MIB_IF_ROW2,
        MIB_UNICASTIPADDRESS_TABLE,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};

fn is_easytier_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    let mut words = lower.split_ascii_whitespace();
    let first = words.next().unwrap_or_default();
    if first == "easytier" || first.starts_with("easytier-") {
        return true;
    }
    // EasyTier's Windows default is et_<interface count>_<four random characters>.
    // The driver's description appends " Tunnel" to the chosen interface alias.
    let Some((count, suffix)) = first.strip_prefix("et_").and_then(|s| s.split_once('_')) else {
        return false;
    };
    matches!(words.next(), None | Some("tunnel"))
        && !count.is_empty()
        && count.bytes().all(|c| c.is_ascii_digit())
        && suffix.len() == 4
        && suffix.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn name(value: &[u16]) -> String {
    let len = value.iter().position(|c| *c == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

pub(super) struct ExcludedAdapters {
    ips: HashSet<IpAddr>,
    indices: HashSet<u32>,
}

impl ExcludedAdapters {
    pub(super) fn read() -> ResultType<Self> {
        let mut raw = std::ptr::null_mut::<MIB_UNICASTIPADDRESS_TABLE>();
        // IP Helper allocates one variable-length table. FreeMibTable is its matching release.
        let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut raw) };
        if status != 0 || raw.is_null() {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        struct Table(*mut MIB_UNICASTIPADDRESS_TABLE);
        impl Drop for Table {
            fn drop(&mut self) {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
        let table = Table(raw);
        let rows = unsafe {
            std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
        };
        let mut seen = HashSet::new();
        let mut excluded = Self {
            ips: HashSet::new(),
            indices: HashSet::new(),
        };
        for row in rows {
            let index = row.InterfaceIndex;
            if seen.insert(index) {
                let mut info: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
                info.InterfaceIndex = index;
                if unsafe { GetIfEntry2(&mut info) } == 0
                    && (is_easytier_name(&name(&info.Alias))
                        || is_easytier_name(&name(&info.Description)))
                {
                    excluded.indices.insert(index);
                }
            }
            if excluded.indices.contains(&index) {
                // si_family selects the active SOCKADDR_INET union member.
                let addr = unsafe {
                    match row.Address.si_family {
                        AF_INET => IpAddr::V4(Ipv4Addr::from(
                            row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                        )),
                        AF_INET6 => IpAddr::V6(Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte)),
                        _ => continue,
                    }
                };
                excluded.ips.insert(addr);
            }
        }
        Ok(excluded)
    }

    pub(super) fn contains(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip)
    }

    fn check_route(&self, dest: IpAddr) -> ResultType<()> {
        let addr = socket2::SockAddr::from(SocketAddr::new(dest, 0));
        let mut index = 0;
        // SockAddr owns an initialized SOCKADDR_IN/IN6 for the whole synchronous call.
        let status = unsafe { GetBestInterfaceEx(addr.as_ptr().cast(), &mut index) };
        if status != 0 {
            anyhow::bail!("Could not verify the selected Windows ICE route");
        }
        if self.indices.contains(&index) {
            anyhow::bail!("ICE selected an excluded EasyTier route");
        }
        Ok(())
    }
}

// In pinned webrtc 0.13 the nominated pair's endpoints are private. Its Display prints
// address:port immediately followed by related_address (without a separator). Match the
// separately typed IP and port from candidate stats, allowing only a valid related IP suffix.
fn selected_base(token: &str, ip: IpAddr, port: u16) -> Option<IpAddr> {
    let suffix = token.strip_prefix(&format!("{ip}:{port}"))?;
    if suffix.is_empty() {
        Some(ip)
    } else {
        suffix.parse().ok()
    }
}

pub(super) async fn check_selected(pc: &RTCPeerConnection) -> ResultType<()> {
    let excluded = ExcludedAdapters::read()?;
    if excluded.indices.is_empty() {
        return Ok(());
    }
    let pair = pc
        .sctp()
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
        .await
        .ok_or_else(|| anyhow::anyhow!("No selected ICE pair"))?
        .to_string();
    let (local, remote) = pair
        .split_once(" <-> ")
        .ok_or_else(|| anyhow::anyhow!("Cannot identify selected ICE pair"))?;
    let (local, remote) = (
        local.split_whitespace().nth(3),
        remote.split_whitespace().nth(3),
    );
    let mut found = (false, false);
    for entry in pc.get_stats().await.reports.into_values() {
        match entry {
            StatsReportType::LocalCandidate(c) => {
                if let Ok(ip) = c.ip.parse::<IpAddr>() {
                    if let Some(base) = local.and_then(|s| selected_base(s, ip, c.port)) {
                        found.0 = true;
                        if excluded.contains(ip) || excluded.contains(base) {
                            anyhow::bail!("ICE selected an excluded EasyTier address");
                        }
                    }
                }
            }
            StatsReportType::RemoteCandidate(c) => {
                if let Ok(ip) = c.ip.parse::<IpAddr>() {
                    if remote.and_then(|s| selected_base(s, ip, c.port)).is_some() {
                        found.1 = true;
                        excluded.check_route(ip)?;
                    }
                }
            }
            _ => {}
        }
    }
    if !found.0 || !found.1 {
        anyhow::bail!("Cannot verify the selected Windows ICE candidate addresses");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_easytier_without_excluding_other_tunnels() {
        for alias in [
            "EasyTier",
            "EasyTier Adapter",
            "et_2_kpij",
            "et_10_m7ah Tunnel",
        ] {
            assert!(is_easytier_name(alias));
        }
        for alias in [
            "Ethernet",
            "Wintun",
            "Meta",
            "Clash Tunnel",
            "et_support",
            "et_1_wired",
        ] {
            assert!(!is_easytier_name(alias));
        }
    }

    #[test]
    fn selected_endpoints_allow_related_addresses_and_unbracketed_ipv6() {
        let v4 = "192.0.2.1".parse().unwrap();
        let v6 = "2001:db8::b".parse().unwrap();
        assert_eq!(
            selected_base("192.0.2.1:3510010.1.2.3", v4, 35100),
            Some("10.1.2.3".parse().unwrap())
        );
        assert_eq!(selected_base("2001:db8::b:35500", v6, 35500), Some(v6));
        assert_eq!(selected_base("192.0.2.10:35500", v4, 35500), None);
        assert_eq!(selected_base("192.0.2.1:35500", v4, 3550), None);
    }
}
