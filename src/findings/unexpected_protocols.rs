use std::collections::BTreeMap;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "ot.unexpected_protocols",
    title: "Non-OT protocols observed touching OT subnets",
    severity: Severity::Medium,
    trigger: "Fires when a flow whose src or dst is inside a configured \
              `--ot-subnet` carries a protocol label from the no-fly \
              list — currently anydesk, apns, bittorrent, gcm, irc, \
              openvpn, rtmp, sip, smtp, stun, teamviewer. Labels come \
              from the port-based flow classifier in \
              `observe.rs::classify_flow`, so the false positive is a \
              service that happens to use a no-fly port for an unrelated \
              reason. Findings tag every offending protocol independently.",
    data_source: &["flows (label matches no-fly list)"],
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
                    "{} -> {}:{} ({} pkts, {} conns)",
                    host_label(flow.key.src, obs),
                    host_label(flow.key.dst, obs),
                    flow.key.dst_port,
                    flow.packets,
                    flow.connections()
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

    let has_remote_access = counts
        .keys()
        .any(|k| matches!(*k, "openvpn" | "teamviewer" | "anydesk"));
    let has_p2p_or_consumer = counts
        .keys()
        .any(|k| matches!(*k, "bittorrent" | "irc" | "sip" | "rtmp"));
    let has_email_or_messaging = counts.keys().any(|k| matches!(*k, "smtp" | "apns" | "gcm"));

    let mut playbook = vec![format!(
        "Identify the device(s) using each unexpected protocol. The evidence list shows \
             source → destination per flow. Walk each source IP to a physical switch port (use \
             `show mac address-table` and the asset inventory's MAC for that host).",
    )];
    if has_remote_access {
        playbook.push(
            "Remote-access tools (TeamViewer / AnyDesk / OpenVPN) on OT are usually vendor \
             support paths someone left running. Either (a) document the exception with named \
             contractor and revocation date and add to the firewall allow-list, or (b) remove. \
             Do NOT block at the switch until the device is identified — vendor remote-access \
             paths are sometimes load-bearing for plant operations and yanking them mid-shift \
             can cause an availability event."
                .to_string(),
        );
    }
    if has_p2p_or_consumer {
        playbook.push(
            "Peer-to-peer / consumer protocols (BitTorrent, IRC, SIP, streaming) on a plant \
             VLAN almost always mean a contractor laptop, an employee personal device, or a \
             compromised host. Isolate the source on a quarantine VLAN, image for forensics \
             if there's any sign of compromise, replace the device."
                .to_string(),
        );
    }
    if has_email_or_messaging {
        playbook.push(
            "Email / push-notification protocols (SMTP, APNs, GCM) on OT either mean (a) a \
             misplaced IT asset on the wrong VLAN — fix the port assignment — or (b) an \
             intentionally on-OT host that shouldn't be sending mail / phoning home. Either \
             way the path needs to close."
                .to_string(),
        );
    }
    playbook.push(
        "After the immediate response, audit the switch port-security policy on this VLAN. A \
         controlled OT VLAN should have static MAC bindings or 802.1X. Random devices \
         appearing with internet-bound traffic means port hygiene is its own finding worth \
         tracking."
            .to_string(),
    );

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
        playbook,
    }]
}

#[cfg(test)]
mod tests {
    #[test]
    fn metadata_trigger_lists_all_eleven_labels() {
        let trigger = super::METADATA.trigger;
        for label in [
            "anydesk",
            "apns",
            "bittorrent",
            "gcm",
            "irc",
            "openvpn",
            "rtmp",
            "sip",
            "smtp",
            "stun",
            "teamviewer",
        ] {
            assert!(
                trigger.contains(label),
                "METADATA.trigger missing label {label:?} — current text: {trigger:?}",
            );
        }
    }

    #[test]
    fn metadata_trigger_uses_src_or_dst_zone_phrasing() {
        let trigger = super::METADATA.trigger;
        let lower = trigger.to_ascii_lowercase();
        assert!(
            lower.contains("src or dst") || lower.contains("source or destination"),
            "METADATA.trigger should say 'src OR dst in OT' but reads: {trigger:?}",
        );
    }

    /// BC-AUDIT-009 — lock the port-to-label table.
    /// One positive assertion per label currently returned by
    /// `unexpected_label`. If a future refactor drops a row or renames
    /// a label, this test fails.
    #[test]
    fn unexpected_label_lookups_match_canonical_table() {
        use super::unexpected_label;

        // tcp/25, 587, 465 → smtp
        assert_eq!(unexpected_label(6, 25), Some("smtp"));
        assert_eq!(unexpected_label(6, 587), Some("smtp"));
        assert_eq!(unexpected_label(6, 465), Some("smtp"));

        // tcp/6881..=6889 → bittorrent
        assert_eq!(unexpected_label(6, 6881), Some("bittorrent"));
        assert_eq!(unexpected_label(6, 6885), Some("bittorrent"));
        assert_eq!(unexpected_label(6, 6889), Some("bittorrent"));
        // udp/6881..=6889 → bittorrent
        assert_eq!(unexpected_label(17, 6881), Some("bittorrent"));
        assert_eq!(unexpected_label(17, 6889), Some("bittorrent"));

        // tcp/1935 → rtmp
        assert_eq!(unexpected_label(6, 1935), Some("rtmp"));

        // tcp/5223 → apns
        assert_eq!(unexpected_label(6, 5223), Some("apns"));

        // tcp/5228..=5230 → gcm
        assert_eq!(unexpected_label(6, 5228), Some("gcm"));
        assert_eq!(unexpected_label(6, 5229), Some("gcm"));
        assert_eq!(unexpected_label(6, 5230), Some("gcm"));

        // udp/3478, 3479 → stun
        assert_eq!(unexpected_label(17, 3478), Some("stun"));
        assert_eq!(unexpected_label(17, 3479), Some("stun"));

        // tcp/5060, udp/5060 → sip
        assert_eq!(unexpected_label(6, 5060), Some("sip"));
        assert_eq!(unexpected_label(17, 5060), Some("sip"));

        // tcp/6667, 6697 → irc
        assert_eq!(unexpected_label(6, 6667), Some("irc"));
        assert_eq!(unexpected_label(6, 6697), Some("irc"));

        // tcp/1194, udp/1194 → openvpn
        assert_eq!(unexpected_label(6, 1194), Some("openvpn"));
        assert_eq!(unexpected_label(17, 1194), Some("openvpn"));

        // tcp/5938 → teamviewer
        assert_eq!(unexpected_label(6, 5938), Some("teamviewer"));

        // tcp/7070, 6568 → anydesk
        assert_eq!(unexpected_label(6, 7070), Some("anydesk"));
        assert_eq!(unexpected_label(6, 6568), Some("anydesk"));
    }

    /// Sentinel: ports NOT in the table return None.
    #[test]
    fn unexpected_label_returns_none_for_unmapped_ports() {
        use super::unexpected_label;

        // Common ports that should NOT be in this no-fly list:
        // - tcp/23 (telnet) — caught by creds.telnet, not unexpected_protocols
        // - tcp/80 (http) — normal traffic
        // - tcp/443 (https) — normal traffic
        // - tcp/22 (ssh) — normal admin
        // - tcp/502 (modbus) — OT
        assert_eq!(
            unexpected_label(6, 23),
            None,
            "telnet handled by creds.telnet"
        );
        assert_eq!(unexpected_label(6, 80), None);
        assert_eq!(unexpected_label(6, 443), None);
        assert_eq!(unexpected_label(6, 22), None);
        assert_eq!(unexpected_label(6, 502), None);
        assert_eq!(unexpected_label(6, 0), None);
        assert_eq!(unexpected_label(6, 65535), None);
    }

    /// Sentinel: unsupported protocols return None.
    #[test]
    fn unexpected_label_returns_none_for_non_tcp_udp() {
        use super::unexpected_label;

        // ICMP=1, GRE=47, ESP=50, SCTP=132 — never in this table.
        assert_eq!(unexpected_label(1, 5060), None);
        assert_eq!(unexpected_label(47, 1194), None);
        assert_eq!(unexpected_label(50, 6881), None);
        assert_eq!(unexpected_label(132, 5938), None);
    }

    /// Lock the LABEL SET — fails if any label string is renamed.
    /// This complements the positive assertions: even if a future refactor
    /// changes a port mapping, the set of distinct labels in the table
    /// stays exactly these 11.
    #[test]
    fn unexpected_label_distinct_label_set_is_exactly_eleven() {
        use super::unexpected_label;
        use std::collections::BTreeSet;

        let mut labels: BTreeSet<&str> = BTreeSet::new();
        // Sweep a small subset that covers every (proto, port) row in the table.
        let probes: &[(u8, u16)] = &[
            (6, 25),
            (6, 6881),
            (17, 6881),
            (6, 1935),
            (6, 5223),
            (6, 5228),
            (17, 3478),
            (6, 5060),
            (17, 5060),
            (6, 6667),
            (6, 1194),
            (17, 1194),
            (6, 5938),
            (6, 7070),
            (6, 6568),
        ];
        for &(proto, port) in probes {
            if let Some(label) = unexpected_label(proto, port) {
                labels.insert(label);
            }
        }
        // 11 distinct labels: smtp, bittorrent, rtmp, apns, gcm, stun, sip, irc, openvpn, teamviewer, anydesk
        assert_eq!(
            labels.len(),
            11,
            "expected exactly 11 distinct labels in the no-fly table; got {labels:?}"
        );
        for expected in [
            "smtp",
            "bittorrent",
            "rtmp",
            "apns",
            "gcm",
            "stun",
            "sip",
            "irc",
            "openvpn",
            "teamviewer",
            "anydesk",
        ] {
            assert!(
                labels.contains(expected),
                "label {expected:?} missing from no-fly table; got {labels:?}"
            );
        }
    }
}
