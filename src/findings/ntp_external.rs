use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "boundary.ntp_external",
    title: "OT host syncing time to public NTP",
    severity: Severity::Medium,
    trigger: "Fires when at least one flow with `dst_port = 123` (UDP) has a \
              source IP inside a configured `--ot-subnet` and a destination IP \
              that is NOT inside any configured OT subnet. OT devices should \
              sync time to an in-zone NTP server under change control; queries \
              to external NTP servers (including public pool addresses) leak \
              timing behaviour across the OT/IT boundary and introduce a \
              dependency on the external network for a safety-critical function.",
    data_source: &["flows (dst_port = 123; src in OT, dst not in OT)"],
    references: &[
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-3 SR-5.1 — Network segmentation",
            url: None,
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "Purdue Reference Model — boundary services",
            url: None,
        },
    ],
};

pub fn detect(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let in_ot = |ip: &IpAddr| ot_subnets.iter().any(|n| n.contains(ip));

    // Walk logical flows. An external-NTP flow is: src in OT, dst not in OT,
    // dst_port == 123 (NTP).
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), u64> = BTreeMap::new();
    for flow in obs.flows.values() {
        if flow.key.dst_port != 123 {
            continue;
        }
        if !in_ot(&flow.key.src) || in_ot(&flow.key.dst) {
            continue;
        }
        *by_pair.entry((flow.key.src, flow.key.dst)).or_insert(0) += flow.packets;
    }

    if by_pair.is_empty() {
        return Vec::new();
    }

    let total_queries: u64 = by_pair.values().sum();
    let mut sorted: Vec<((IpAddr, IpAddr), u64)> = by_pair.iter().map(|(k, v)| (*k, *v)).collect();
    sorted.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    let evidence: Vec<String> = sorted
        .iter()
        .take(15)
        .map(|((src, dst), n)| {
            format!(
                "{} -> {}:123 (UDP, {n} packet(s))",
                host_label(*src, obs),
                host_label(*dst, obs),
            )
        })
        .collect();

    let distinct_clients: std::collections::BTreeSet<IpAddr> =
        sorted.iter().map(|((s, _), _)| *s).collect();
    let client_list = format_host_list(&distinct_clients);

    let summary = format!(
        "{} OT host(s) sending NTP queries to time sources outside the configured OT subnets \
         ({total_queries} total query packet(s)). OT devices should sync time to an in-zone \
         NTP server under change control; relying on external time sources introduces a \
         dependency on the external network for a safety-critical function and leaks timing \
         behaviour across the OT/IT boundary.",
        distinct_clients.len()
    );

    let playbook = vec![
        format!(
            "Identify each source host's configured NTP server: {client_list}. \
             On Windows: `w32tm /query /source` shows the active time source per host. \
             On Linux: `chronyc sources` (chrony) or `timedatectl show-timesync` (systemd-timesyncd). \
             Do not change anything yet — read-only identification step."
        ),
        "Check the asset inventory in this report for any host already acting as an in-zone \
         NTP server. A host receiving NTP queries on UDP/123 from within the OT subnet and \
         that is itself inside the OT subnet is a candidate in-zone time source. If one \
         exists, reconfigure the listed clients to point at it."
            .to_string(),
        "If no in-zone NTP server exists, stand one up inside the OT zone (or in a dedicated \
         DMZ). Chrony on a hardened OT bastion is the standard software pattern — it supports \
         multiple upstream sources, has a small attack surface, and logs all sync events. \
         For hard real-time requirements (sub-millisecond), prefer a GPS or PTP (IEEE 1588) \
         grandmaster clock instead."
            .to_string(),
        "Once OT clients are repointed at the in-zone time source, add an outbound UDP/123 \
         deny rule at the IT/OT firewall for OT subnets (excluding the new NTP server itself). \
         This ensures any host that reverts to an external NTP address fails visibly rather \
         than silently drifting."
            .to_string(),
        "Cross-reference the destination IPs against known public NTP pools (pool.ntp.org, \
         time.windows.com, time.apple.com, etc.). A destination matching a public pool is a \
         clear external dependency; a destination that is an internal IT address is a \
         different gap (routing / policy) but still violates zone separation — both cases \
         require remediation."
            .to_string(),
    ];

    vec![Finding {
        id: "boundary.ntp_external",
        severity: Severity::Medium,
        title: "NTP queries to a public time source".to_string(),
        summary,
        evidence,
        recommendation: "Repoint OT hosts at an in-zone (or DMZ-relayed) NTP server. \
                          For hard real-time requirements use GPS or PTP (IEEE 1588). \
                          Add an outbound UDP/123 deny rule at the IT/OT boundary for \
                          everything except the sanctioned time source(s).",
        playbook,
    }]
}

fn format_host_list(hosts: &std::collections::BTreeSet<IpAddr>) -> String {
    let v: Vec<IpAddr> = hosts.iter().copied().collect();
    match v.len() {
        0 => "the listed hosts".to_string(),
        1 => format!("`{}`", v[0]),
        2 => format!("`{}` and `{}`", v[0], v[1]),
        n if n <= 4 => v
            .iter()
            .map(|ip| format!("`{ip}`"))
            .collect::<Vec<_>>()
            .join(", "),
        _ => format!("`{}` and {} other host(s)", v[0], v.len() - 1),
    }
}
