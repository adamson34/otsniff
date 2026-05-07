use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::observe::Observations;

use super::{Finding, Severity};

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
            .map(|((src, dst), fcs)| format!("{src} -> {dst} : {}", fcs.to_vec().join(", ")))
            .collect();

        let unknown_origin = modbus_eng
            .iter()
            .any(|e| !ot_subnets.iter().any(|n| n.contains(&e.src)));
        let severity = if unknown_origin {
            Severity::Critical
        } else {
            Severity::High
        };

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
            .map(|((src, dst), svcs)| format!("{src} -> {dst} : {}", svcs.join(", ")))
            .collect();

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
        });
    }

    out
}
