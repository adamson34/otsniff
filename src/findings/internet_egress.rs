use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "egress.ot_to_internet",
    title: "Internet-bound traffic from OT subnets",
    severity: Severity::Critical,
    trigger: "Fires when at least one packet has been seen with a source \
              IP inside a configured `--ot-subnet` and a destination IP \
              that is public (not RFC1918, not link-local, not loopback, \
              not multicast, not broadcast, and not in a documented \
              IPv6 ULA range). Aggregates by the (src, dst, dst_port, \
              proto) tuple; one finding fires regardless of how many \
              flows match.",
    data_source: &["external_flows"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0883 — Internet Accessible Device",
            url: Some("https://attack.mitre.org/techniques/T0883/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-3 SR-5.1 — Network segmentation",
            url: None,
        },
    ],
};

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

    let mut categories: Vec<&str> = Vec::new();
    let has_dns = flows.iter().any(|f| f.dst_port == 53);
    let has_ntp = flows.iter().any(|f| f.dst_port == 123);
    let has_tunnel = flows
        .iter()
        .any(|f| matches!(f.dst_port, 1194 | 4500 | 500 | 51820));
    if has_dns {
        categories.push("DNS to a non-OT resolver");
    }
    if has_ntp {
        categories.push("NTP to an external server");
    }
    if has_tunnel {
        categories.push("an encrypted tunnel (OpenVPN / IPsec / WireGuard)");
    }

    let mut playbook = vec![
        "Identify the IT/OT gateway physically. The flows below traverse it — look at the asset \
         inventory for hosts whose MACs appear on both sides of the boundary (a single MAC \
         showing up for an OT IP and a public IP is the gateway interface)."
            .to_string(),
        "Pull the running config / ruleset from the gateway (firewall, L3 switch, or whatever \
         serves as the OT boundary). Look for an explicit deny-all-by-default with named \
         exceptions. The expected answer for a plant boundary is \"deny everything; allow \
         these specific update servers / vendor cloud endpoints / time sources.\""
            .to_string(),
        "Cross-reference each flow in the evidence against that ruleset. Any flow not covered \
         by an explicit allow is either a missing rule or a control gap — both worth fixing."
            .to_string(),
    ];
    if !categories.is_empty() {
        playbook.push(format!(
            "Specific categories seen here: {}. For each, the standard fix is: DNS → move OT \
             clients to an in-zone resolver or DMZ relay; NTP → use a sanctioned in-zone time \
             source; encrypted tunnels → identify the source host before blocking, treat as a \
             standing remote-access path until proven otherwise.",
            categories.join(", ")
        ));
    }
    playbook.push(
        "After the rules are tightened, log the changes in the change-management system and \
         re-capture in 24 hours to confirm the egress is blocked."
            .to_string(),
    );

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
        playbook,
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
