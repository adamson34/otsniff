use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "boundary.dns_resolver",
    title: "DNS queries from OT to an out-of-zone resolver",
    severity: Severity::Medium,
    trigger: "Fires when at least one flow with `dst_port = 53` has a \
              source IP inside a configured `--ot-subnet` and a \
              destination IP that is NOT inside any configured OT \
              subnet. Cross-zone DNS leaks query patterns to the IT \
              side and trusts an external resolver's answers; both \
              the resolution path and the DNS server itself should be \
              in-zone under change control.",
    data_source: &["flows (dst_port = 53; src in OT, dst not in OT)"],
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

    // Walk logical flows. A non-OT-resolver flow is: src in OT, dst not
    // in OT, dst_port == 53.
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), u64> = BTreeMap::new();
    for flow in obs.flows.values() {
        if flow.key.dst_port != 53 {
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
                "{} -> {}:53 (UDP/TCP, {n} packet(s))",
                host_label(*src, obs),
                host_label(*dst, obs),
            )
        })
        .collect();

    let distinct_clients: std::collections::BTreeSet<IpAddr> =
        sorted.iter().map(|((s, _), _)| *s).collect();
    let client_list = format_host_list(&distinct_clients);

    let summary = format!(
        "{} OT host(s) sending DNS queries to resolvers outside the configured OT subnets \
         ({total_queries} total query packet(s)). Cross-zone DNS leaks query patterns to \
         the IT side and trusts an external resolver's answers. Both belong on the OT side \
         under change control.",
        distinct_clients.len()
    );

    let playbook = vec![
        format!(
            "Identify each source host's configured DNS server: {client_list}. \
             On Windows: `ipconfig /all` shows DNS Servers per interface. \
             On Linux: `/etc/resolv.conf` (or `systemd-resolve --status` on systemd hosts). \
             Don't change anything yet — read-only check."
        ),
        "Verify whether an in-zone resolver exists. The asset inventory in this report shows \
         which OT hosts speak DNS — a host running a DNS server on the OT side will show up \
         with `dns` in its protocol list. If one exists, the listed clients should point at it."
            .to_string(),
        "If no in-zone resolver: stand one up in the OT zone (or a dedicated DMZ). Configure \
         it with a strict upstream relationship — only resolves a known set of plant-relevant \
         names; everything else fails closed. CoreDNS or BIND with a small zone file is the \
         standard pattern here."
            .to_string(),
        "Once OT clients are repointed at the in-zone resolver, add an outbound UDP/53 deny \
         rule at the IT/OT firewall for OT subnets that aren't the resolver itself. This \
         catches any host that gets reverted to its old config and prevents cross-zone DNS \
         from being a quiet failure mode."
            .to_string(),
        "Cross-reference the destination resolver IPs against your IT team's documented DNS \
         infrastructure. If a host is querying a known public resolver (Google, Cloudflare, \
         etc.) that's a different problem than querying an internal IT resolver — the public \
         case is also caught by the egress finding; the internal case is a routing / config \
         gap on the OT side."
            .to_string(),
    ];

    vec![Finding {
        id: "boundary.dns_resolver",
        severity: Severity::Medium,
        title: "DNS queries to a non-OT resolver".to_string(),
        summary,
        evidence,
        recommendation: "Repoint OT hosts at an in-zone (or DMZ-relayed) DNS resolver. Add an outbound UDP/53 deny rule at the IT/OT boundary for everything except the sanctioned resolver(s).",
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
