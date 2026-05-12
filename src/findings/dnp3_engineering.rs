//! ics.dnp3_engineering finding emitter.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "ics.dnp3_engineering",
    title: "DNP3 engineering-class commands on the wire",
    severity: Severity::High,
    trigger: "Fires when a DNP3 master issues engineering-class function codes \
              (Operate (4), Direct Operate (5), Direct Operate No Ack (6), \
              Cold Restart (13), Warm Restart (14), Initialize Data (15), \
              Initialize Application (16), Disable Unsolicited (20), \
              Enable Unsolicited (21), Save Configuration (24)) against a \
              controller. DNP3 has no native authentication in its base \
              specification; any host that can reach a DNP3 outstation on \
              tcp/20000 can send these commands.",
    data_source: &["dnp3_events (where engineering_class = true)"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0855 — Unauthorized Command Message",
            url: Some("https://attack.mitre.org/techniques/T0855/"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0836 — Modify Parameter",
            url: Some("https://attack.mitre.org/techniques/T0836/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "IEEE 1815-2012 — DNP3 Standard",
            url: None,
        },
    ],
};

pub fn detect(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let eng: Vec<_> = obs
        .dnp3_events
        .iter()
        .filter(|e| e.engineering_class)
        .collect();

    if eng.is_empty() {
        return Vec::new();
    }

    let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<u8>> = BTreeMap::new();
    for ev in &eng {
        let entry = by_pair.entry((ev.src, ev.dst)).or_default();
        if entry.len() < 5 {
            entry.push(ev.function_code);
        }
    }

    let evidence: Vec<String> = by_pair
        .iter()
        .take(15)
        .map(|((src, dst), fcs)| {
            let fc_str: Vec<String> = fcs.iter().map(|fc| format!("fc={fc}")).collect();
            format!(
                "{} -> {} : {}",
                host_label(*src, obs),
                host_label(*dst, obs),
                fc_str.join(", ")
            )
        })
        .collect();

    let unknown_origin = eng
        .iter()
        .any(|e| !ot_subnets.iter().any(|n| n.contains(&e.src)));
    let severity = if unknown_origin {
        Severity::Critical
    } else {
        Severity::High
    };

    let src_ips: std::collections::BTreeSet<IpAddr> = by_pair.keys().map(|(src, _)| *src).collect();
    let dst_ips: std::collections::BTreeSet<IpAddr> = by_pair.keys().map(|(_, dst)| *dst).collect();
    let sources_str = format_ip_list(&src_ips.into_iter().collect::<Vec<_>>());
    let dests_str = format_ip_list(&dst_ips.into_iter().collect::<Vec<_>>());

    let playbook = vec![
        format!(
            "Identify the source host(s) physically: {sources_str}. DNP3 masters are \
             typically SCADA front-end processors or engineering workstations. Use the \
             MAC-to-switch-port table (`show mac address-table address <mac>`) to locate \
             the physical port.",
        ),
        format!(
            "Confirm with the on-shift control engineer whether {sources_str} is the \
             authorized DNP3 master for {dests_str}. Authorized masters are listed in \
             the site's ICS asset register. If yes, the finding is expected but verify \
             there are no other hosts with access.",
        ),
        "DNP3 Secure Authentication (SA v5 / IEEE 1815-2012 Annex A) should be \
         enabled on all outstations that support it. Without SA, any reachable host \
         can send engineering commands."
            .to_string(),
        format!(
            "If the source is not an authorized master, ACL the switch so only the \
             authorized master can reach tcp/20000 on {dests_str}. Coordinate with \
             operations before applying — an unexpected ACL on a DNP3 path is an \
             availability event.",
        ),
    ];

    vec![Finding {
        id: "ics.dnp3_engineering",
        severity,
        title: "DNP3 engineering-class commands on the wire".to_string(),
        summary: format!(
            "{} DNP3 engineering-class command(s) observed across {} master→outstation pair(s). \
             DNP3 has no native authentication; any host that can reach an outstation on \
             tcp/20000 can send these commands.",
            eng.len(),
            by_pair.len()
        ),
        evidence,
        recommendation: "Enable DNP3 Secure Authentication (SA v5) on outstations that support it \
                         and ACL tcp/20000 to authorized masters only.",
        playbook,
    }]
}

fn format_ip_list(ips: &[IpAddr]) -> String {
    match ips.len() {
        0 => "the host(s) below".to_string(),
        1 => format!("`{}`", ips[0]),
        2 => format!("`{}` and `{}`", ips[0], ips[1]),
        n if n <= 4 => {
            let mut s = String::new();
            for (i, ip) in ips.iter().enumerate() {
                if i > 0 && i == ips.len() - 1 {
                    s.push_str(", and ");
                } else if i > 0 {
                    s.push_str(", ");
                }
                s.push('`');
                s.push_str(&ip.to_string());
                s.push('`');
            }
            s
        }
        _ => format!("`{}` and {} other host(s)", ips[0], ips.len() - 1),
    }
}
