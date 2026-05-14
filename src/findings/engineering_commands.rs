use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const MODBUS_METADATA: RuleMetadata = RuleMetadata {
    id: "ics.modbus_writes",
    title: "Modbus engineering-class commands on the wire",
    severity: Severity::High,
    trigger: "Fires when one or more Modbus/TCP requests have a function \
              code that writes or changes device state. Function-code \
              level only — no payload deep-parse. The engineering class \
              includes: 0x05 (Write Single Coil), 0x06 (Write Single \
              Register), 0x0F (Write Multiple Coils), 0x10 (Write \
              Multiple Registers), 0x16 (Mask Write Register), 0x17 \
              (Read/Write Multiple Registers), 0x08 (Diagnostics — \
              includes Restart Communication), 0x15 (Write File \
              Record), and FC 8 sub-function 1 (Force Listen Only Mode). \
              Modbus has no authentication; any host reaching tcp/502 \
              can issue these.",
    data_source: &["modbus_events (where engineering_class = true)"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0836 — Modify Parameter",
            url: Some("https://attack.mitre.org/techniques/T0836/"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0855 — Unauthorized Command Message",
            url: Some("https://attack.mitre.org/techniques/T0855/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "Modbus Application Protocol Specification v1.1b3",
            url: None,
        },
    ],
};

pub const ENIP_METADATA: RuleMetadata = RuleMetadata {
    id: "ics.cip_engineering",
    title: "EtherNet/IP engineering-class CIP services",
    severity: Severity::High,
    trigger: "Fires when an EtherNet/IP encapsulation request contains a \
              CIP service we classify as engineering — Stop, Reset, \
              Apply Attributes, Forward Close to a controller-class \
              object. Function-code level only; we don't reconstruct \
              CIP path semantics. Like Modbus, ENIP/CIP has no native \
              authentication.",
    data_source: &["enip_events (where engineering_class = true)"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0858 — Change Operating Mode",
            url: Some("https://attack.mitre.org/techniques/T0858/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "ODVA CIP Vol. 1 (Common Industrial Protocol)",
            url: None,
        },
    ],
};

pub const S7_METADATA: RuleMetadata = RuleMetadata {
    id: "ics.s7_engineering",
    title: "S7Comm engineering-class commands on the wire",
    severity: Severity::High,
    trigger: "Fires when S7Comm (Siemens S7-300/400/1200/1500 over \
              tcp/102) traffic contains a function code we classify as \
              engineering — 0x05 Write Var, 0x1A-0x1C block download, \
              0x1D-0x1F block upload, 0x28 PLC Control (hot / cold \
              restart sub-types), 0x29 PLC Stop. S7Comm has no native \
              authentication; S7-1500 adds Secure Communication only \
              when explicitly enabled.",
    data_source: &["s7_events (where engineering_class = true)"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0858 — Change Operating Mode",
            url: Some("https://attack.mitre.org/techniques/T0858/"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0843 — Program Download",
            url: Some("https://attack.mitre.org/techniques/T0843/"),
        },
        Reference {
            kind: ReferenceKind::Vendor,
            label: "Siemens — S7 Communication overview (industrial security)",
            url: None,
        },
    ],
};

pub fn detect(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let mut out = Vec::new();

    let modbus_eng: Vec<_> = obs
        .modbus_events
        .iter()
        .filter(|e| e.engineering_class)
        .collect();

    let enip_eng: Vec<_> = obs
        .enip_events
        .iter()
        .filter(|e| e.engineering_class)
        .collect();

    let s7_eng: Vec<_> = obs
        .s7_events
        .iter()
        .filter(|e| e.engineering_class)
        .collect();

    if !modbus_eng.is_empty() {
        let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<String>> = BTreeMap::new();
        for ev in &modbus_eng {
            let entry = by_pair.entry((ev.src, ev.dst)).or_default();
            if entry.len() < 5 {
                entry.push(format!("fc=0x{:02X} ({})", ev.function_code, ev.label));
            }
        }
        let evidence: Vec<String> = by_pair
            .iter()
            .take(15)
            .map(|((src, dst), fcs)| {
                format!(
                    "{} -> {} : {}",
                    host_label(*src, obs),
                    host_label(*dst, obs),
                    fcs.to_vec().join(", ")
                )
            })
            .collect();

        let unknown_origin = modbus_eng
            .iter()
            .any(|e| !ot_subnets.iter().any(|n| n.contains(&e.src)));
        let severity = if unknown_origin {
            Severity::Critical
        } else {
            Severity::High
        };

        let sources_str = pair_sources_str(&by_pair);
        let dests_str = pair_dests_str(&by_pair);
        let playbook = vec![
            format!(
                "Identify the source host(s) physically: {sources_str}. Run \
                 `show mac address-table address <mac>` on the access switch (or your switch \
                 vendor's equivalent), then walk the cable. The asset inventory in this report \
                 has the MAC for each host.",
            ),
            format!(
                "Ask the on-shift control engineer whether {sources_str} is the authorized \
                 Modbus master for {dests_str}. Common authorized masters: SCADA servers, \
                 Niagara N4 supervisors, RTUs polling downstream PLCs. If yes, the finding is \
                 expected — but the host hygiene (other ports open on the asset inventory) is \
                 worth a separate look.",
            ),
            format!(
                "Pull session / event logs from {dests_str}. Most controllers can show which \
                 coil and register addresses were written, with timestamps. Cross-reference \
                 against change-management tickets covering the capture window.",
            ),
            "If the source is not an authorized writer, do NOT block at the switch yet. An \
             unexpected ACL on a Modbus path is an availability event. Coordinate with \
             operations first — schedule the change, run it past the control engineer."
                .to_string(),
            "Once the unauthorized path is confirmed: ACL the switch port (or VLAN) so only \
             the authorized writer can reach tcp/502 on the target controllers. Consider \
             Modbus-aware filtering (DPI) in front of safety-critical PLCs."
                .to_string(),
        ];

        out.push(Finding {
            id: "ics.modbus_writes",
            severity,
            title: "Modbus engineering-class commands on the wire".to_string(),
            summary: format!(
                "{} write/diagnostic Modbus call(s) observed across {} client→server pair(s). Modbus has no authentication; any host that can reach a controller on tcp/502 can change plant state.",
                modbus_eng.len(),
                by_pair.len()
            ),
            evidence,
            recommendation: "Enumerate which hosts are allowed to write to controllers and ACL the rest at the switch/firewall. Consider Modbus-aware filtering (deep-packet inspection) in front of safety-critical PLCs.",
            playbook,
        });
    }

    if !enip_eng.is_empty() {
        let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<String>> = BTreeMap::new();
        for ev in &enip_eng {
            let entry = by_pair.entry((ev.src, ev.dst)).or_default();
            if entry.len() < 5 {
                entry.push(format!(
                    "{} / {}",
                    ev.command_label,
                    ev.cip_service.clone().unwrap_or_else(|| "?".to_string())
                ));
            }
        }
        let evidence: Vec<String> = by_pair
            .iter()
            .take(15)
            .map(|((src, dst), svcs)| {
                format!(
                    "{} -> {} : {}",
                    host_label(*src, obs),
                    host_label(*dst, obs),
                    svcs.join(", ")
                )
            })
            .collect();

        let sources_str = pair_sources_str(&by_pair);
        let dests_str = pair_dests_str(&by_pair);
        let playbook = vec![
            format!(
                "Identify the source host(s) physically: {sources_str}. Use the same MAC-table \
                 approach as for the Modbus playbook. Engineering workstations running Studio \
                 5000 / RSLogix or Rockwell Connected Components Workbench are the usual \
                 culprits.",
            ),
            "Lock controller keyswitches to RUN or REMOTE-ONLY where possible. Allen-Bradley \
             ControlLogix, CompactLogix, and Micro800-series controllers physically refuse \
             program downloads in those positions."
                .to_string(),
            format!(
                "In Studio 5000 (or the equivalent for your platform), pull the controller's \
                 audit log and download history for {dests_str}. Look for unauthorized \
                 program downloads, online edits, or tag changes during the capture window.",
            ),
            "Limit which engineering workstations can reach controllers on tcp/44818 + \
             udp/2222 via switch ACL or firewall rule. Engineering access should be a known-\
             IP allow list, not \"everyone on the OT VLAN.\""
                .to_string(),
            "If any unauthorized download is confirmed, treat as a controller-integrity \
             incident. Plan a recovery window with operations to verify the running program \
             against a known-good backup before resuming."
                .to_string(),
        ];

        out.push(Finding {
            id: "ics.cip_engineering",
            severity: Severity::High,
            title: "EtherNet/IP CIP engineering-class services observed".to_string(),
            summary: format!(
                "{} CIP engineering-class request(s) (Set/Reset/Start/Stop/Forward Open with config) seen across {} pair(s). These services change controller configuration or run state.",
                enip_eng.len(),
                by_pair.len()
            ),
            evidence,
            recommendation: "Limit which engineering workstations can talk to controllers on tcp/44818 + udp/2222. Lock controller keyswitches to RUN/REMOTE-ONLY where possible to refuse program downloads.",
            playbook,
        });
    }

    if !s7_eng.is_empty() {
        let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<String>> = BTreeMap::new();
        for ev in &s7_eng {
            let entry = by_pair.entry((ev.src, ev.dst)).or_default();
            if entry.len() < 5 {
                entry.push(format!("fc=0x{:02X} ({})", ev.function_code, ev.label));
            }
        }
        let evidence: Vec<String> = by_pair
            .iter()
            .take(15)
            .map(|((src, dst), fcs)| {
                format!(
                    "{} -> {} : {}",
                    host_label(*src, obs),
                    host_label(*dst, obs),
                    fcs.to_vec().join(", ")
                )
            })
            .collect();

        let unknown_origin = s7_eng
            .iter()
            .any(|e| !ot_subnets.iter().any(|n| n.contains(&e.src)));
        let severity = if unknown_origin {
            Severity::Critical
        } else {
            Severity::High
        };

        // Categorize the engineering events for a more specific summary.
        let download_count = s7_eng
            .iter()
            .filter(|e| matches!(e.function_code, 0x1A..=0x1C))
            .count();
        let upload_count = s7_eng
            .iter()
            .filter(|e| matches!(e.function_code, 0x1D..=0x1F))
            .count();
        let plc_control_count = s7_eng
            .iter()
            .filter(|e| matches!(e.function_code, 0x28 | 0x29))
            .count();
        let write_count = s7_eng.iter().filter(|e| e.function_code == 0x05).count();

        let mut categories = Vec::new();
        if write_count > 0 {
            categories.push(format!("{write_count} write(s)"));
        }
        if download_count > 0 {
            categories.push(format!("{download_count} download op(s)"));
        }
        if upload_count > 0 {
            categories.push(format!("{upload_count} upload op(s)"));
        }
        if plc_control_count > 0 {
            categories.push(format!("{plc_control_count} CPU control op(s)"));
        }
        let category_str = if categories.is_empty() {
            String::new()
        } else {
            format!(" — {}", categories.join(", "))
        };

        let sources_str = pair_sources_str(&by_pair);
        let dests_str = pair_dests_str(&by_pair);
        let mut playbook = vec![
            format!(
                "Identify the source host(s) physically: {sources_str}. For TIA Portal / Step \
                 7 Manager-class hosts, expect a Windows engineering laptop or a permanent \
                 PG.",
            ),
            format!(
                "In TIA Portal, set the controller's access level on {dests_str} to \"no \
                 access (complete protection)\" or \"read access\" — anything looser allows \
                 variable writes from anyone reaching tcp/102.",
            ),
            format!(
                "Pull the controller diagnostic buffer for {dests_str} (TIA Portal: Online & \
                 Diagnostics → Diagnostic Buffer). Look for download events, mode changes \
                 (RUN → STOP), and password-protection changes during the capture window.",
            ),
            "For S7-1500: enable Secure Communication with TLS and pin the controller's \
             certificate. For S7-300/400 (no native TLS): physical keyswitch lock plus a \
             switch-level ACL is the path."
                .to_string(),
        ];
        if plc_control_count > 0 || download_count > 0 {
            playbook.push(
                "STOP commands or program downloads were seen — treat as a controller-\
                 integrity incident. Compare the running program against a known-good \
                 project backup before resuming production. Plan a recovery window with \
                 operations."
                    .to_string(),
            );
        }

        out.push(Finding {
            id: "ics.s7_engineering",
            severity,
            title: "S7Comm engineering-class commands on the wire".to_string(),
            summary: format!(
                "{} S7 engineering call(s){} across {} client→server pair(s). S7Comm has no authentication; any host that can reach a controller on tcp/102 can read/write variables, download programs, or stop the CPU.",
                s7_eng.len(),
                category_str,
                by_pair.len()
            ),
            evidence,
            recommendation: "Limit which engineering workstations can talk to controllers on tcp/102. For S7-1500 / TIA Portal environments, set the controller access level to \"no access (complete protection)\" or \"read access\" and require known-fingerprint TLS via Secure Communication. For older S7-300/400, use switch ACLs and physically lock the keyswitch to RUN.",
            playbook,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-006 Red Gate: S7_METADATA.trigger must NOT mention "password".
    /// The word crept in as an erroneous classifier label ("password operations")
    /// and must be removed so the trigger accurately lists only real S7Comm
    /// engineering function codes (PLC stop/start, block download/upload).
    /// This test will FAIL until the production string is corrected.
    #[test]
    fn s7_metadata_trigger_does_not_mention_password() {
        assert!(
            !S7_METADATA.trigger.contains("password"),
            "S7_METADATA.trigger still mentions 'password': {}",
            S7_METADATA.trigger
        );
        assert!(
            S7_METADATA.trigger.contains("PLC stop")
                || S7_METADATA.trigger.contains("block download")
                || S7_METADATA.trigger.contains("upload"),
            "S7_METADATA.trigger should list real engineering classifiers (PLC stop, block download, upload): {}",
            S7_METADATA.trigger
        );
    }
}

fn pair_sources_str(by_pair: &BTreeMap<(IpAddr, IpAddr), Vec<String>>) -> String {
    let sources: std::collections::BTreeSet<IpAddr> = by_pair.keys().map(|(src, _)| *src).collect();
    format_ip_list(&sources.into_iter().collect::<Vec<_>>())
}

fn pair_dests_str(by_pair: &BTreeMap<(IpAddr, IpAddr), Vec<String>>) -> String {
    let dests: std::collections::BTreeSet<IpAddr> = by_pair.keys().map(|(_, dst)| *dst).collect();
    format_ip_list(&dests.into_iter().collect::<Vec<_>>())
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
