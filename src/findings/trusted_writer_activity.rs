//! `ics.trusted_writer_activity` finding emitter (P1-12, ADR-0015).
//!
//! Rolls up operator-declared trusted engineering-command activity across
//! all four ICS protocols into a single Info-severity finding, rather than
//! a `_trusted` variant per protocol (D3 in
//! `docs/specs/trusted-writer-allowlist.md`). The four engineering-command
//! detectors (`engineering_commands`, `dnp3_engineering`) independently
//! exclude these same trusted pairs from their own High/Critical findings
//! (D2) — this module only builds the Info rollup and the unmatched-
//! declaration set used for the stderr warning.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::observe::Observations;
use crate::trusted_writer::{classify, TrustedWriterRule, WriterProto};

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "ics.trusted_writer_activity",
    title: "Trusted engineering-command activity (operator-declared)",
    severity: Severity::Info,
    trigger: "Fires when one or more Modbus / EtherNet-IP CIP / S7Comm / \
              DNP3 engineering-class commands match a client\u{2192}server \
              pair declared via `--trusted-writer`. This reflects an \
              UNVERIFIED operator assertion, not evidence that the traffic \
              was authenticated \u{2014} IPs are spoofable and otsniff is a \
              passive PCAP tool. It exists so the High/Critical \
              engineering-command findings can report only pairs that were \
              not declared, instead of re-flagging the same known-good \
              writer every run.",
    data_source: &[
        "modbus_events (where engineering_class = true)",
        "enip_events (where engineering_class = true)",
        "s7_events (where engineering_class = true)",
        "dnp3_events (where engineering_class = true)",
    ],
    references: &[Reference {
        kind: ReferenceKind::Spec,
        label: "ADR-0015 — Operator-declared trusted writers may lower finding severity",
        url: None,
    }],
};

/// One evidence row: which protocol, which pair, which declaration matched.
struct Row {
    protocol: &'static str,
    src: IpAddr,
    dst: IpAddr,
    rule_index: usize,
    details: Vec<String>,
}

pub fn detect(obs: &Observations, trusted_writers: &[TrustedWriterRule]) -> Vec<Finding> {
    if trusted_writers.is_empty() {
        return Vec::new();
    }

    let mut rows: Vec<Row> = Vec::new();
    let mut matched: BTreeSet<usize> = BTreeSet::new();

    collect(
        &mut rows,
        &mut matched,
        "modbus",
        obs.modbus_events
            .iter()
            .filter(|e| e.engineering_class)
            .map(|e| {
                (
                    e.src,
                    e.dst,
                    format!("fc=0x{:02X} ({})", e.function_code, e.label),
                )
            }),
        trusted_writers,
        WriterProto::Modbus,
    );
    collect(
        &mut rows,
        &mut matched,
        "cip",
        obs.enip_events
            .iter()
            .filter(|e| e.engineering_class)
            .map(|e| {
                (
                    e.src,
                    e.dst,
                    format!(
                        "{} / {}",
                        e.command_label,
                        e.cip_service.clone().unwrap_or_else(|| "?".to_string())
                    ),
                )
            }),
        trusted_writers,
        WriterProto::Cip,
    );
    collect(
        &mut rows,
        &mut matched,
        "s7",
        obs.s7_events
            .iter()
            .filter(|e| e.engineering_class)
            .map(|e| {
                (
                    e.src,
                    e.dst,
                    format!("fc=0x{:02X} ({})", e.function_code, e.label),
                )
            }),
        trusted_writers,
        WriterProto::S7,
    );
    collect(
        &mut rows,
        &mut matched,
        "dnp3",
        obs.dnp3_events
            .iter()
            .filter(|e| e.engineering_class)
            .map(|e| (e.src, e.dst, format!("fc={}", e.function_code))),
        trusted_writers,
        WriterProto::Dnp3,
    );

    if rows.is_empty() {
        return Vec::new();
    }

    let pair_count = rows.len();
    let event_count: usize = rows.iter().map(|r| r.details.len()).sum();
    let width = rows.iter().map(|r| r.protocol.len()).max().unwrap_or(0);
    let evidence: Vec<String> = rows
        .iter()
        .take(30)
        .map(|r| {
            format!(
                "{:width$}: {} -> {} : {}  [trusted-writer {}]",
                r.protocol,
                host_label(r.src, obs),
                host_label(r.dst, obs),
                r.details.join(", "),
                r.rule_index,
            )
        })
        .collect();

    vec![Finding {
        id: "ics.trusted_writer_activity",
        severity: Severity::Info,
        title: "Trusted engineering-command activity (operator-declared)".to_string(),
        summary: format!(
            "{event_count} engineering-class call(s) across {pair_count} declared \
             client\u{2192}server pair(s) matched a `--trusted-writer` declaration. \
             Severity was reduced by operator declaration \u{2014} this is not proof \
             the traffic was authenticated."
        ),
        evidence,
        recommendation: "Review the declared pairs periodically; a stale entry naming a \
                          decommissioned host silently lowers severity for anyone who \
                          reuses that IP.",
        playbook: vec![
            "This finding exists only because `--trusted-writer` was passed for this \
             run. Confirm the declared pairs are still the correct authorized writers \
             \u{2014} an IP reassignment or decommissioned engineering workstation can \
             make a stale declaration match an unrelated, untrusted host."
                .to_string(),
            "The declaration is an assertion, not a verification: it does not prove the \
             traffic was authenticated. Treat it as a triage aid, not a compliance \
             control."
                .to_string(),
        ],
    }]
}

fn collect(
    rows: &mut Vec<Row>,
    matched: &mut BTreeSet<usize>,
    protocol: &'static str,
    events: impl Iterator<Item = (IpAddr, IpAddr, String)>,
    trusted_writers: &[TrustedWriterRule],
    proto: WriterProto,
) {
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), (usize, Vec<String>)> = BTreeMap::new();
    for (src, dst, detail) in events {
        let Some(rule_index) = classify(trusted_writers, src, dst, proto) else {
            continue;
        };
        matched.insert(rule_index);
        let entry = by_pair
            .entry((src, dst))
            .or_insert_with(|| (rule_index, Vec::new()));
        if entry.1.len() < 5 {
            entry.1.push(detail);
        }
    }
    for ((src, dst), (rule_index, details)) in by_pair {
        rows.push(Row {
            protocol,
            src,
            dst,
            rule_index,
            details,
        });
    }
}

/// Declared-rule indices (1-based) matched by at least one engineering
/// event in `obs`, across all four protocols. Used by the CLI to warn on
/// stderr about declarations that matched nothing (a typo or a
/// decommissioned host).
pub fn matched_rule_indices(
    obs: &Observations,
    trusted_writers: &[TrustedWriterRule],
) -> BTreeSet<usize> {
    let mut matched = BTreeSet::new();
    for e in obs.modbus_events.iter().filter(|e| e.engineering_class) {
        if let Some(i) = classify(trusted_writers, e.src, e.dst, WriterProto::Modbus) {
            matched.insert(i);
        }
    }
    for e in obs.enip_events.iter().filter(|e| e.engineering_class) {
        if let Some(i) = classify(trusted_writers, e.src, e.dst, WriterProto::Cip) {
            matched.insert(i);
        }
    }
    for e in obs.s7_events.iter().filter(|e| e.engineering_class) {
        if let Some(i) = classify(trusted_writers, e.src, e.dst, WriterProto::S7) {
            matched.insert(i);
        }
    }
    for e in obs.dnp3_events.iter().filter(|e| e.engineering_class) {
        if let Some(i) = classify(trusted_writers, e.src, e.dst, WriterProto::Dnp3) {
            matched.insert(i);
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{Dnp3Event, ModbusEvent};
    use chrono::Utc;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn modbus_event(src: &str, dst: &str) -> ModbusEvent {
        ModbusEvent {
            ts: Utc::now(),
            src: ip(src),
            dst: ip(dst),
            function_code: 0x10,
            label: "Write Multiple Registers".to_string(),
            engineering_class: true,
        }
    }

    fn dnp3_event(src: &str, dst: &str) -> Dnp3Event {
        Dnp3Event {
            ts: Utc::now(),
            src: ip(src),
            dst: ip(dst),
            function_code: 4,
            engineering_class: true,
        }
    }

    #[test]
    fn no_finding_without_trusted_writers() {
        let mut obs = Observations::default();
        obs.modbus_events
            .push(modbus_event("10.20.0.5", "10.20.0.10"));
        assert!(detect(&obs, &[]).is_empty());
    }

    #[test]
    fn no_finding_when_nothing_matches() {
        let mut obs = Observations::default();
        obs.modbus_events
            .push(modbus_event("10.20.0.5", "10.20.0.10"));
        let rules = vec!["9.9.9.9=9.9.9.8:modbus".parse().unwrap()];
        assert!(detect(&obs, &rules).is_empty());
    }

    #[test]
    fn fires_and_carries_protocol_and_rule_index_in_evidence() {
        let mut obs = Observations::default();
        obs.modbus_events
            .push(modbus_event("10.20.0.5", "10.20.0.10"));
        obs.dnp3_events.push(dnp3_event("10.20.0.5", "10.20.0.22"));
        let rules = vec![
            "10.20.0.5=10.20.0.10:modbus".parse().unwrap(),
            "10.20.0.5=10.20.0.22:dnp3".parse().unwrap(),
        ];
        let findings = detect(&obs, &rules);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "ics.trusted_writer_activity");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence.len(), 2);
        assert!(f
            .evidence
            .iter()
            .any(|l| l.starts_with("modbus") && l.contains("[trusted-writer 1]")));
        assert!(f
            .evidence
            .iter()
            .any(|l| l.starts_with("dnp3") && l.contains("[trusted-writer 2]")));
    }

    #[test]
    fn matched_rule_indices_tracks_hits_only() {
        let mut obs = Observations::default();
        obs.modbus_events
            .push(modbus_event("10.20.0.5", "10.20.0.10"));
        let rules = vec![
            "10.20.0.5=10.20.0.10:modbus".parse().unwrap(),
            "10.20.0.5=10.20.0.11:s7".parse().unwrap(),
        ];
        let matched = matched_rule_indices(&obs, &rules);
        assert_eq!(matched, BTreeSet::from([1]));
    }
}
