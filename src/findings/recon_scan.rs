//! recon.port_scan detector — fires when a single source contacts many
//! distinct destinations (horizontal) or many distinct (port, proto)
//! combinations (vertical) within the capture window.
//!
//! One finding per scanning source IP, classified as horizontal, vertical,
//! or combined. Broadcast/multicast destinations are excluded from counts.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

/// Minimum distinct destination IPs before a horizontal-scan finding fires.
const DST_THRESHOLD: usize = 10;

/// Minimum distinct (dst_port, proto) pairs before a vertical-scan finding fires.
const PORT_THRESHOLD: usize = 10;

/// Destination count at which severity escalates from Medium to High.
const HIGH_THRESHOLD_DST: usize = 50;

/// (port, proto) count at which severity escalates from Medium to High.
const HIGH_THRESHOLD_PORT: usize = 50;

/// Maximum evidence rows per finding (mirrors sibling detectors).
const MAX_EVIDENCE: usize = 15;

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "recon.port_scan",
    title: "Port scan — source host probing many destinations or ports",
    severity: Severity::Medium,
    trigger: "Fires when a single source IP contacts >= 10 distinct destinations \
              (horizontal scan) OR >= 10 distinct (port, protocol) combinations \
              (vertical scan) within the capture window. Severity escalates to \
              High at >= 50. One finding per scanning source, classified as \
              horizontal, vertical, or combined. Broadcast/multicast destinations \
              are skipped.",
    data_source: &[
        "flows (grouped by src_ip; counting distinct dst_ip and (dst_port, proto) pairs)",
    ],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0846 — Remote System Discovery",
            url: Some("https://attack.mitre.org/techniques/T0846/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-3 SR-7.7 — Least privilege",
            url: None,
        },
    ],
};

/// Accumulated scan metrics for a single source IP.
#[derive(Default)]
struct ScanGroup {
    dsts: BTreeSet<IpAddr>,
    ports: BTreeSet<(u16, u8)>,
    total_flows: usize,
}

pub fn detect(obs: &Observations, _ot_subnets: &[IpNet]) -> Vec<Finding> {
    // Group flows by source IP.
    let mut by_src: BTreeMap<IpAddr, ScanGroup> = BTreeMap::new();

    for flow in obs.flows.values() {
        let dst = flow.key.dst;
        if is_broadcast_or_multicast(dst) {
            continue;
        }
        let entry = by_src.entry(flow.key.src).or_default();
        entry.dsts.insert(dst);
        entry.ports.insert((flow.key.dst_port, flow.key.proto));
        entry.total_flows += 1;
    }

    let mut findings = Vec::new();

    for (src, g) in by_src {
        if g.dsts.len() < DST_THRESHOLD && g.ports.len() < PORT_THRESHOLD {
            continue;
        }

        let severity = if g.dsts.len() >= HIGH_THRESHOLD_DST || g.ports.len() >= HIGH_THRESHOLD_PORT
        {
            Severity::High
        } else {
            Severity::Medium
        };

        let classification = classify(g.dsts.len(), g.ports.len());
        let src_label = host_label(src, obs);

        // Evidence summary rows.
        let mut evidence: Vec<String> = vec![
            format!(
                "{src_label} (scanning host): {} distinct destinations",
                g.dsts.len()
            ),
            format!("{} distinct (port, proto) combinations", g.ports.len()),
            format!("Classification: {classification}"),
            format!("Total flows: {}", g.total_flows),
        ];

        let sample_dsts: Vec<String> = g
            .dsts
            .iter()
            .take(MAX_EVIDENCE)
            .map(|d| host_label(*d, obs))
            .collect();
        evidence.push(format!("Top destinations: {}", sample_dsts.join(", ")));

        let sample_ports: Vec<String> = g
            .ports
            .iter()
            .take(MAX_EVIDENCE)
            .map(|(p, proto)| format!("{}/{}", p, proto_label(*proto)))
            .collect();
        evidence.push(format!("Sample ports: {}", sample_ports.join(", ")));

        let title = format!(
            "Port scan: {src_label} probed {} host(s) across {} (port, proto) combination(s) \
             [{classification}]",
            g.dsts.len(),
            g.ports.len()
        );

        let summary = format!(
            "{src_label} contacted {} distinct destination(s) across {} (port, proto) \
             combination(s) [{classification}] within the capture window — consistent with \
             a port scan or host-discovery sweep. Broadcast and multicast addresses were \
             excluded from the count.",
            g.dsts.len(),
            g.ports.len()
        );

        let playbook = vec![
            format!(
                "Identify whether {src_label} is an authorized scanner (e.g., a Nessus / \
                 OpenVAS sensor, patch-management agent, or OT asset-discovery tool). \
                 Check your change-management records and asset-inventory for that host."
            ),
            format!(
                "If the host is NOT an authorized scanner, treat this as a potential \
                 lateral-movement precursor. Isolate {src_label} and inspect its process \
                 list and network connections for unknown tooling."
            ),
            format!(
                "Review the {} target host(s) and {} (port, proto) combination(s): were \
                 they all expected to be reachable from {src_label}? Tighten firewall rules \
                 at the OT/IT boundary to block lateral scanning between zones.",
                g.dsts.len(),
                g.ports.len()
            ),
            "If this is a known-good scanner, add it to an explicit allowlist and suppress \
             this finding with `--ot-subnet` tuning or a future ignore-list feature."
                .to_string(),
        ];

        findings.push(Finding {
            id: METADATA.id,
            severity,
            title,
            summary,
            evidence,
            recommendation: "Verify whether the source host is an authorised scanner. \
                             If not, isolate and investigate for lateral-movement activity. \
                             Restrict inter-zone scanning at the firewall.",
            playbook,
        });
    }

    findings
}

/// Classify the scan pattern based on dst spread and port spread.
///
/// "horizontal" — many destinations, few ports (≤ 3 port combinations)
/// "vertical"   — few destinations (≤ 3), many ports
/// "combined"   — both spreads are large
fn classify(dst_count: usize, port_count: usize) -> &'static str {
    match (dst_count, port_count) {
        (d, p) if d >= DST_THRESHOLD && p <= 3 => "horizontal",
        (d, p) if d <= 3 && p >= PORT_THRESHOLD => "vertical",
        _ => "combined",
    }
}

fn is_broadcast_or_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

fn proto_label(p: u8) -> &'static str {
    match p {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "ip",
    }
}
