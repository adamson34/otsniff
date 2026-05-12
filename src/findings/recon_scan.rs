//! recon.port_scan detector — fires when a single source talks to
//! many distinct destinations on the same port within the capture.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

/// Minimum number of distinct destination IPs on the same (src, dst_port,
/// proto) tuple before the finding fires. Tunable — raise this for noisier
/// environments where 5 distinct targets is plausible normal traffic.
const PORT_SCAN_THRESHOLD: usize = 5;

/// Destination count at which severity escalates from Medium to High.
const PORT_SCAN_HIGH_THRESHOLD: usize = 25;

/// Maximum evidence rows per finding (mirrors the per-finding cap used by
/// sibling detectors — keeps report HTML readable).
const MAX_EVIDENCE: usize = 15;

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "recon.port_scan",
    title: "Port scan — single source to many destinations on the same port",
    severity: Severity::Medium,
    trigger: "Fires when a single source IP talks to >= 5 distinct destination \
              IPs on the same destination port + protocol within the capture \
              window (PORT_SCAN_THRESHOLD = 5). Severity escalates to High at \
              >= 25 distinct destinations. Broadcast and multicast destination \
              addresses are excluded from the count.",
    data_source: &["flows (grouped by src_ip, dst_port, proto; counting distinct dst_ip)"],
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

pub fn detect(obs: &Observations, _ot_subnets: &[IpNet]) -> Vec<Finding> {
    // Group flows by (src_ip, dst_port, proto) → set of distinct unicast dst IPs.
    let mut groups: BTreeMap<(IpAddr, u16, u8), BTreeSet<IpAddr>> = BTreeMap::new();

    for flow in obs.flows.values() {
        let dst = flow.key.dst;
        if is_broadcast_or_multicast(dst) {
            continue;
        }
        groups
            .entry((flow.key.src, flow.key.dst_port, flow.key.proto))
            .or_default()
            .insert(dst);
    }

    let mut findings = Vec::new();

    for ((src, dst_port, proto), dsts) in &groups {
        let count = dsts.len();
        if count < PORT_SCAN_THRESHOLD {
            continue;
        }

        let severity = if count >= PORT_SCAN_HIGH_THRESHOLD {
            Severity::High
        } else {
            Severity::Medium
        };

        let proto_str = proto_label(*proto);
        let src_label = host_label(*src, obs);

        let evidence: Vec<String> = dsts
            .iter()
            .take(MAX_EVIDENCE)
            .map(|dst_ip| {
                format!(
                    "{src_label} -> {}:{dst_port}/{proto_str}",
                    host_label(*dst_ip, obs),
                )
            })
            .collect();

        let summary = format!(
            "{src_label} contacted {count} distinct destination(s) on {proto_str}/{dst_port} \
             within the capture window — consistent with a port scan or host-discovery sweep. \
             Broadcast and multicast addresses were excluded from the count.",
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
                "Review the {count} target host(s) on {proto_str}/{dst_port}: were they all \
                 expected to be reachable from {src_label}? Tighten firewall rules at the \
                 OT/IT boundary to block lateral scanning between zones."
            ),
            "If this is a known-good scanner, add it to an explicit allowlist and suppress \
             this finding with `--ot-subnet` tuning or a future ignore-list feature."
                .to_string(),
        ];

        findings.push(Finding {
            id: METADATA.id,
            severity,
            title: format!(
                "Port scan: {src_label} probed {count} host(s) on {proto_str}/{dst_port}"
            ),
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
