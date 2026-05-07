use std::collections::BTreeMap;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{Finding, Severity};

/// Protocols that have no legitimate place on a plant control network.
/// Hitting any of these from an OT-zone host is a posture finding.
fn unexpected_label(proto: u8, port: u16) -> Option<&'static str> {
    match (proto, port) {
        (6, 25) | (6, 587) | (6, 465) => Some("smtp"),
        (6, 6881..=6889) => Some("bittorrent"),
        (17, 6881..=6889) => Some("bittorrent"),
        (6, 1935) => Some("rtmp"),
        (6, 5223) => Some("apns"),
        (6, 5228..=5230) => Some("gcm"),
        (17, 3478) | (17, 3479) => Some("stun"),
        (6, 5060) | (17, 5060) => Some("sip"),
        (6, 6667) | (6, 6697) => Some("irc"),
        (6, 1194) | (17, 1194) => Some("openvpn"),
        (6, 5938) => Some("teamviewer"),
        (6, 7070) => Some("anydesk"),
        (6, 6568) => Some("anydesk"),
        _ => None,
    }
}

pub fn detect(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let mut hits: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();

    for flow in obs.flows.values() {
        let in_ot_src = ot_subnets.iter().any(|n| n.contains(&flow.key.src));
        let in_ot_dst = ot_subnets.iter().any(|n| n.contains(&flow.key.dst));
        if !in_ot_src && !in_ot_dst {
            continue;
        }
        if let Some(label) = unexpected_label(flow.key.proto, flow.key.dst_port) {
            *counts.entry(label).or_insert(0) += 1;
            let bucket = hits.entry(label).or_default();
            if bucket.len() < 5 {
                bucket.push(format!(
                    "{}:{} -> {}:{} ({} pkts)",
                    flow.key.src, flow.key.src_port, flow.key.dst, flow.key.dst_port, flow.packets
                ));
            }
        }
    }

    if hits.is_empty() {
        return Vec::new();
    }

    let labels: Vec<String> = counts
        .iter()
        .map(|(k, n)| format!("{k} ({n} flow(s))"))
        .collect();

    let evidence: Vec<String> = hits.values().flat_map(|v| v.iter().cloned()).collect();

    vec![Finding {
        id: "ot.unexpected_protocols",
        severity: Severity::Medium,
        title: "Non-OT protocols observed touching OT subnets".to_string(),
        summary: format!(
            "Saw {}: {}. None of these belong on a plant control network; their presence usually points to an unauthorized device, vendor laptop, or routing/firewall mistake.",
            if labels.len() == 1 { "a flow type that shouldn't be on OT" } else { "flow types that shouldn't be on OT" },
            labels.join(", ")
        ),
        evidence,
        recommendation: "Trace each source to a physical port. Block at the access switch and document an exception process for any tool (e.g. remote-access software) that legitimately needs to cross the IT/OT boundary.",
    }]
}
