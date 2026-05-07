use crate::observe::Observations;

use super::{Finding, Severity};

pub fn detect(obs: &Observations) -> Vec<Finding> {
    if obs.external_flows.is_empty() {
        return Vec::new();
    }

    let mut flows: Vec<_> = obs.external_flows.values().collect();
    flows.sort_by_key(|f| std::cmp::Reverse(f.bytes));

    let total_flows = flows.len();
    let total_bytes: u64 = flows.iter().map(|f| f.bytes).sum();
    let evidence: Vec<String> = flows
        .iter()
        .take(15)
        .map(|f| {
            format!(
                "{} -> {}:{} ({}, {} pkts, {} bytes)",
                f.src,
                f.dst,
                f.dst_port,
                proto_label(f.proto),
                f.packets,
                f.bytes
            )
        })
        .collect();

    vec![Finding {
        id: "egress.ot_to_internet",
        severity: Severity::Critical,
        title: "Internet-bound traffic from OT subnets".to_string(),
        summary: format!(
            "Saw {total_flows} distinct flow(s) ({} bytes total) from hosts inside the configured OT subnets to public internet addresses. Plant networks should be egress-restricted at the IT/OT boundary.",
            total_bytes
        ),
        evidence,
        recommendation: "Audit the IT/OT firewall ruleset. OT zones should only egress to specifically allowed update servers and vendor cloud endpoints, brokered through a DMZ with logging. Block, then add explicit allow rules.",
    }]
}

fn proto_label(p: u8) -> &'static str {
    match p {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "ip",
    }
}
