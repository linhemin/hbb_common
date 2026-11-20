//! On-device summaries of one ICE agent. Never serialize the raw WebRTC stats report.
use super::WebRTCStream;
use std::{
    fmt::Write,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use webrtc::{
    ice::candidate::{CandidatePairState, CandidateType},
    ice_transport::ice_candidate::RTCIceCandidate,
    stats::{ICECandidatePairStats, StatsReport, StatsReportType},
};

const BUDGET: Duration = Duration::from_millis(250);
const MAX_REPORTS: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Public4,
    Other4,
    V6,
    Unknown,
}

const SCOPES: [Scope; 4] = [Scope::Public4, Scope::Other4, Scope::V6, Scope::Unknown];

impl Scope {
    fn of(address: &str) -> Self {
        match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Self::v4(ip),
            Ok(IpAddr::V6(ip)) => ip.to_ipv4_mapped().map_or(Self::V6, Self::v4),
            Err(_) => Self::Unknown,
        }
    }

    fn v4(ip: Ipv4Addr) -> Self {
        // Includes shared, service-continuity, benchmark, documentation and reserved space.
        // 192.0.0.9 and .10 are the globally reachable PCP/TURN anycast assignments.
        let [a, b, c, d] = ip.octets();
        if a == 0
            || a >= 224
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_loopback()
            || ip.is_documentation()
            || (a == 100 && (64..=127).contains(&b))
            || (a == 198 && matches!(b, 18 | 19))
            || (a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
            || (a == 192 && b == 88 && c == 99)
        {
            Self::Other4
        } else {
            Self::Public4
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Public4 => "public4",
            Self::Other4 => "other4",
            Self::V6 => "ipv6",
            Self::Unknown => "unknown",
        }
    }
}

// Column order is part of the text report and appears in its header.
#[derive(Default)]
struct PairCounts {
    pairs: usize,
    states: [usize; 5],
    nominated: usize,
    traffic: [u64; 6],
}

impl PairCounts {
    fn add(&mut self, pair: &ICECandidatePairStats) {
        self.pairs += 1;
        self.nominated += usize::from(pair.nominated);
        self.states[match pair.state {
            CandidatePairState::Waiting => 0,
            CandidatePairState::InProgress => 1,
            CandidatePairState::Succeeded => 2,
            CandidatePairState::Failed => 3,
            CandidatePairState::Unspecified => 4,
        }] += 1;
        let counters = [
            pair.requests_sent,
            pair.request_send_failures,
            pair.requests_received,
            pair.responses_sent,
            pair.response_send_failures,
            pair.responses_received,
        ];
        for (sum, value) in self.traffic.iter_mut().zip(counters) {
            *sum = sum.saturating_add(value);
        }
    }
}

fn kind_index(kind: CandidateType) -> usize {
    match kind {
        CandidateType::Host => 0,
        CandidateType::ServerReflexive => 1,
        CandidateType::PeerReflexive => 2,
        CandidateType::Relay => 3,
        CandidateType::Unspecified => 4,
    }
}

fn append_stats(out: &mut String, stats: &StatsReport) {
    if stats.reports.len() > MAX_REPORTS {
        out.push_str("checklist=unavailable (stats limit)\n");
        return;
    }
    // The collector keys each candidate by its ICE stats ID. IDs stay in the original report.
    let mut local = [[0usize; 5]; 4];
    let mut remote = [[0usize; 5]; 4];
    let mut by_remote: [PairCounts; 4] = Default::default();
    let mut to_public4: [PairCounts; 4] = Default::default();
    let mut have_ice_stats = false;
    for item in stats.reports.values() {
        match item {
            StatsReportType::CandidatePair(pair) => {
                have_ice_stats = true;
                let remote_scope = match stats.reports.get(&pair.remote_candidate_id) {
                    Some(StatsReportType::RemoteCandidate(c)) => Scope::of(&c.ip),
                    _ => Scope::Unknown,
                };
                by_remote[remote_scope as usize].add(pair);
                if remote_scope == Scope::Public4 {
                    let source = match stats.reports.get(&pair.local_candidate_id) {
                        Some(StatsReportType::LocalCandidate(c)) => Scope::of(&c.ip),
                        _ => Scope::Unknown,
                    };
                    to_public4[source as usize].add(pair);
                }
            }
            StatsReportType::LocalCandidate(c) | StatsReportType::RemoteCandidate(c) => {
                have_ice_stats = true;
                let counts = if matches!(item, StatsReportType::LocalCandidate(_)) {
                    &mut local
                } else {
                    &mut remote
                };
                counts[Scope::of(&c.ip) as usize][kind_index(c.candidate_type)] += 1;
            }
            _ => {}
        }
    }
    if !have_ice_stats {
        out.push_str("checklist=unavailable (no ICE reports)\n");
        return;
    }
    out.push_str("candidates [host,srflx,prflx,relay,unknown]\n");
    for scope in SCOPES {
        let i = scope as usize;
        let _ = writeln!(
            out,
            "{} local={:?} remote={:?}",
            scope.label(),
            local[i],
            remote[i]
        );
    }
    out.push_str("pairs states=[waiting,checking,succeeded,failed,unknown] traffic=[reqSent,reqSendError,reqReceivedValid,respSent,respSendError,respReceivedMatched]\n");
    for scope in SCOPES {
        let p = &by_remote[scope as usize];
        let _ = writeln!(
            out,
            "remote={} pairs={} nominated={} states={:?} traffic={:?}",
            scope.label(),
            p.pairs,
            p.nominated,
            p.states,
            p.traffic
        );
    }
    // A local srflx IP denotes an advertised public endpoint, not a local interface or route.
    for scope in SCOPES {
        let p = &to_public4[scope as usize];
        if p.pairs > 0 {
            let _ = writeln!(
                out,
                "local={}->remote=public4 pairs={} traffic={:?}",
                scope.label(),
                p.pairs,
                p.traffic
            );
        }
    }
}

fn selected(c: &RTCIceCandidate) -> String {
    // Format only known enum types plus a scope we classified ourselves. The candidate's
    // own Display includes its raw IP, port and foundation.
    format!("{}/{}/{}", c.protocol, c.typ, Scope::of(&c.address).label())
}

impl WebRTCStream {
    /// A local, bounded snapshot of this stream's actual ICE checklist (never its SDP).
    /// Only fixed labels, enumerated states and counters may enter the returned text.
    pub async fn ice_path_diagnostics(&self) -> String {
        let sctp = self.pc.sctp();
        let dtls = sctp.transport();
        let ice = dtls.ice_transport();
        let mut out = format!(
            "ice={} dtls={} sctp={} pc={}\n",
            self.pc.ice_connection_state(),
            dtls.state(),
            sctp.state(),
            self.pc.connection_state()
        );
        let (pair, stats) = tokio::join!(
            tokio::time::timeout(BUDGET, ice.get_selected_candidate_pair()),
            tokio::time::timeout(BUDGET, self.pc.get_stats())
        );
        match pair {
            Ok(Some(pair)) => {
                let _ = writeln!(
                    out,
                    "selected={} -> {}",
                    selected(pair.local()),
                    selected(pair.remote())
                );
            }
            Ok(None) => out.push_str("selected=none\n"),
            Err(_) => out.push_str("selected=unknown (timeout)\n"),
        }
        match stats {
            Ok(stats) => append_stats(&mut out, &stats),
            Err(_) => out.push_str("checklist=unavailable (timeout)\n"),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use webrtc::{
        ice::agent::agent_stats::{CandidatePairStats, CandidateStats},
        stats::SourceStatsType,
    };

    #[test]
    fn candidate_scopes_preserve_unavailable_and_special_use() {
        for text in [
            "0.0.0.0",
            "10.2.3.4",
            "100.64.1.2",
            "127.0.0.1",
            "169.254.1.2",
            "172.31.1.2",
            "192.0.0.2",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.2",
            "198.19.1.2",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(Scope::of(text), Scope::Other4, "{text}");
        }
        for text in ["8.8.8.8", "::ffff:8.8.8.8", "192.0.0.9", "192.0.0.10"] {
            assert_eq!(Scope::of(text), Scope::Public4);
        }
        assert_eq!(Scope::of("2001:db8::1"), Scope::V6);
        assert_eq!(Scope::of("redacted.local"), Scope::Unknown);
    }

    #[test]
    fn report_uses_actual_pair_ids_and_never_prints_identifying_fields() {
        let mut reports = HashMap::new();
        let local = CandidateStats {
            id: "local-sensitive-id".into(),
            ip: "10.22.33.44".into(),
            candidate_type: CandidateType::Host,
            port: 48174,
            ..Default::default()
        };
        let remote = CandidateStats {
            id: "remote-sensitive-id".into(),
            ip: "8.8.4.4".into(),
            candidate_type: CandidateType::ServerReflexive,
            port: 58275,
            ..Default::default()
        };
        let pair = CandidatePairStats {
            local_candidate_id: local.id.clone(),
            remote_candidate_id: remote.id.clone(),
            requests_sent: 7,
            request_send_failures: 2,
            requests_received: 3,
            responses_sent: 4,
            response_send_failures: 5,
            responses_received: 6,
            state: CandidatePairState::InProgress,
            ..Default::default()
        };
        reports.insert(
            local.id.clone(),
            SourceStatsType::LocalCandidate(local).into(),
        );
        reports.insert(
            remote.id.clone(),
            SourceStatsType::RemoteCandidate(remote).into(),
        );
        reports.insert(
            "first-pair".into(),
            StatsReportType::CandidatePair(pair.into()),
        );
        let missing = CandidatePairStats {
            local_candidate_id: "local-sensitive-id".into(),
            remote_candidate_id: "missing".into(),
            ..Default::default()
        };
        reports.insert(
            "second-pair".into(),
            StatsReportType::CandidatePair(missing.into()),
        );
        let mut text = String::new();
        append_stats(&mut text, &StatsReport { reports });
        assert!(text.contains("public4 local=[0, 0, 0, 0, 0] remote=[0, 1, 0, 0, 0]"));
        assert!(text.contains("local=other4->remote=public4 pairs=1 traffic=[7, 2, 3, 4, 5, 6]"));
        assert!(text.contains("remote=unknown pairs=1"));
        for private in [
            "sensitive-id",
            "10.22.33.44",
            "8.8.4.4",
            "48174",
            "58275",
            "first-pair",
            "second-pair",
            "missing",
        ] {
            assert!(!text.contains(private));
        }
        assert!(text.len() < 4096);
    }

    #[test]
    fn absent_stats_do_not_imply_zero_traffic() {
        let mut text = String::new();
        append_stats(
            &mut text,
            &StatsReport {
                reports: HashMap::new(),
            },
        );
        assert_eq!(text, "checklist=unavailable (no ICE reports)\n");
    }
}
