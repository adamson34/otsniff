//! `attack.spoofed_sources` finding emitter (P1-10).
//!
//! DoS captures (SYN flood, ping flood) with randomized source addresses
//! produce inventories with thousands of "hosts" that are really one
//! spoofed packet each. Discovered while triaging the Lemay/Fernandez
//! dataset: `eth2dump-pingFloodDDoS` and `eth2dump-tcpSYNFloodDDoS` show
//! 12,005 / 12,017 distinct source IPs — the report inventory becomes
//! unreadable and the host count misleads the analyst about the size of
//! the real network.
//!
//! The fingerprint: a spoofed source sends exactly one packet, gets no
//! reply (nobody routes a response back to an address that isn't really
//! there), never shows a captured MAC (a real host's Ethernet framing
//! records one), and carries no protocol enrichment. A genuine host,
//! even a quiet one, almost always has at least one of those signals.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

/// Roadmap P1-10: fires when more than this many distinct source IPs match
/// the fingerprint. A handful of one-shot, no-reply hosts is unremarkable
/// (a probe that never got answered); thousands of them is a flood.
const THRESHOLD: usize = 500;

/// Evidence/sample cap — keep the finding readable even when the flood
/// count runs into the tens of thousands.
const SAMPLE_CAP: usize = 5;

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "attack.spoofed_sources",
    title: "Spoofed-source flood — mass single-packet ghost hosts",
    severity: Severity::High,
    trigger: "Fires when more than 500 distinct source IPs each match the \
              spoofed-source fingerprint: exactly one packet sent, zero \
              packets ever received in reply, no MAC address captured, and \
              no protocol enrichment. A real host's Ethernet framing \
              records a MAC on every packet, and a real bidirectional \
              exchange gets at least one reply; this shape — thousands of \
              one-shot, unreachable 'hosts' — is what a randomized-source \
              SYN flood or ping flood looks like on the wire, not genuine \
              distinct hosts.",
    data_source: &[
        "hosts (macs, protocols)",
        "flows (per-(src,dst) packet counts)",
    ],
    references: &[Reference {
        kind: ReferenceKind::MitreIcsAttack,
        label: "T0814 — Denial of Service",
        url: Some("https://attack.mitre.org/techniques/T0814/"),
    }],
};

pub fn detect(obs: &Observations) -> Vec<Finding> {
    let mut sent: BTreeMap<IpAddr, u64> = BTreeMap::new();
    let mut received: BTreeMap<IpAddr, u64> = BTreeMap::new();
    for flow in obs.flows.values() {
        *sent.entry(flow.key.src).or_insert(0) += flow.packets;
        *received.entry(flow.key.dst).or_insert(0) += flow.packets;
    }

    let is_suspect = |ip: &IpAddr| -> bool {
        sent.get(ip).copied().unwrap_or(0) == 1
            && received.get(ip).copied().unwrap_or(0) == 0
            && obs
                .hosts
                .get(ip)
                .map(|h| h.macs.is_empty() && h.protocols.is_empty())
                .unwrap_or(true)
    };

    let mut suspects: Vec<IpAddr> = sent.keys().copied().filter(is_suspect).collect();
    if suspects.len() <= THRESHOLD {
        return Vec::new();
    }
    suspects.sort();

    // Primary target(s): the destination(s) these single-shot sources hit.
    let mut targets: BTreeMap<IpAddr, u64> = BTreeMap::new();
    for flow in obs.flows.values() {
        if is_suspect(&flow.key.src) {
            *targets.entry(flow.key.dst).or_insert(0) += flow.packets;
        }
    }
    let mut target_list: Vec<(IpAddr, u64)> = targets.into_iter().collect();
    target_list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let targets_str = target_list
        .iter()
        .take(SAMPLE_CAP)
        .map(|(ip, n)| format!("{ip} ({n} packet(s))"))
        .collect::<Vec<_>>()
        .join(", ");
    let sample_sources = suspects
        .iter()
        .take(SAMPLE_CAP)
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    let evidence = vec![
        format!(
            "{} distinct source IPs match the spoofed-source fingerprint \
             (1 packet sent, 0 received, no MAC, no protocol enrichment)",
            suspects.len()
        ),
        format!("Primary target(s): {targets_str}"),
        format!("Sample sources: {sample_sources}, ..."),
    ];

    vec![Finding {
        id: "attack.spoofed_sources",
        severity: Severity::High,
        title: "Spoofed-source flood — mass single-packet ghost hosts".to_string(),
        summary: format!(
            "{} of the {} distinct IPs seen in this capture are single-packet, no-reply, \
             no-MAC ghosts — the fingerprint of a spoofed-source flood, not genuine hosts. \
             The asset inventory table is capped and summarized accordingly.",
            suspects.len(),
            obs.hosts.len(),
        ),
        evidence,
        recommendation: "Treat the inventory host count as unreliable for this capture. \
                          Investigate the primary target(s) for a SYN/ping-flood DoS \
                          condition and filter spoofed-looking traffic upstream (uRPF / \
                          BCP38 at the network edge) rather than trying to block by source IP.",
        playbook: vec![
            "Confirm the flood is still active: check the primary target(s)' CPU / interface \
             utilization and whether legitimate traffic to them is degraded."
                .to_string(),
            "Enable or verify unicast Reverse Path Forwarding (uRPF) / BCP38 source-address \
             filtering at the network edge — the standard mitigation for spoofed-source \
             floods, and it doesn't require enumerating individual attacker IPs."
                .to_string(),
            "If the target is a safety-critical controller, verify it degrades gracefully \
             under load (fail-safe, not fail-open) rather than assuming the flood is purely \
             a bandwidth nuisance."
                .to_string(),
        ],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{FlowKey, FlowObs, HostObs};
    use chrono::Utc;
    use std::collections::HashSet;

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(n))
    }

    /// Builds an `Observations` with `n` spoofed-fingerprint sources (each
    /// sending exactly one packet to `target`, no reply, no MAC, no
    /// protocol) plus one genuine host that completes a real exchange.
    fn flood_fixture(n: u32) -> Observations {
        let mut obs = Observations::default();
        let target = ip(1);
        let ts = Utc::now();

        obs.hosts.insert(
            target,
            HostObs {
                ip: target,
                macs: vec![[0, 1, 2, 3, 4, 5]],
                protocols: HashSet::new(),
                first_seen: ts,
                last_seen: ts,
                packets: n as u64,
                bytes: 0,
                in_ot_zone: false,
            },
        );

        for i in 0..n {
            let src = ip(1000 + i);
            obs.hosts.insert(
                src,
                HostObs {
                    ip: src,
                    macs: Vec::new(),
                    protocols: HashSet::new(),
                    first_seen: ts,
                    last_seen: ts,
                    packets: 1,
                    bytes: 60,
                    in_ot_zone: false,
                },
            );
            let key = FlowKey {
                src,
                dst: target,
                dst_port: 80,
                proto: 6,
            };
            obs.flows.insert(
                format!("{src}->{target}:80/6"),
                FlowObs {
                    key,
                    packets: 1,
                    bytes: 60,
                    first_seen: ts,
                    last_seen: ts,
                    label: None,
                    unique_src_ports: HashSet::new(),
                },
            );
        }

        // One genuine host: two-way exchange (sends AND receives), so it
        // must never be counted as a suspect regardless of count.
        let genuine = ip(2);
        obs.hosts.insert(
            genuine,
            HostObs {
                ip: genuine,
                macs: vec![[0, 1, 2, 3, 4, 9]],
                protocols: HashSet::from(["tcp".to_string()]),
                first_seen: ts,
                last_seen: ts,
                packets: 2,
                bytes: 120,
                in_ot_zone: false,
            },
        );
        obs.flows.insert(
            format!("{genuine}->{target}:80/6"),
            FlowObs {
                key: FlowKey {
                    src: genuine,
                    dst: target,
                    dst_port: 80,
                    proto: 6,
                },
                packets: 1,
                bytes: 60,
                first_seen: ts,
                last_seen: ts,
                label: None,
                unique_src_ports: HashSet::new(),
            },
        );
        obs.flows.insert(
            format!("{target}->{genuine}:0/6"),
            FlowObs {
                key: FlowKey {
                    src: target,
                    dst: genuine,
                    dst_port: 0,
                    proto: 6,
                },
                packets: 1,
                bytes: 60,
                first_seen: ts,
                last_seen: ts,
                label: None,
                unique_src_ports: HashSet::new(),
            },
        );

        obs
    }

    #[test]
    fn silent_below_threshold() {
        let obs = flood_fixture(500);
        assert!(
            detect(&obs).is_empty(),
            "exactly the threshold count must not fire (roadmap: K > 500)"
        );
    }

    #[test]
    fn fires_above_threshold() {
        let obs = flood_fixture(501);
        let findings = detect(&obs);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "attack.spoofed_sources");
        assert_eq!(f.severity, Severity::High);
        assert!(f.evidence[0].contains("501"));
        assert!(!f.playbook.is_empty());
    }

    #[test]
    fn genuine_two_way_host_never_counted_as_suspect() {
        // Even with a huge flood, the one genuine bidirectional host must
        // never appear in the suspect count (it sends AND receives).
        let obs = flood_fixture(600);
        let findings = detect(&obs);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].evidence[0].contains("600 distinct"),
            "the genuine host must not inflate or deflate the suspect count: {:?}",
            findings[0].evidence
        );
    }

    #[test]
    fn a_host_with_a_mac_is_never_a_suspect() {
        let mut obs = flood_fixture(501);
        // Give one flood "source" a MAC — it now fails the fingerprint and
        // must drop the count below the fire threshold.
        let extra = ip(1000);
        obs.hosts.get_mut(&extra).unwrap().macs.push([9; 6]);
        let findings = detect(&obs);
        assert!(
            findings.is_empty(),
            "a captured MAC disqualifies a host from the spoofed-source fingerprint"
        );
    }
}
