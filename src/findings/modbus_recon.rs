//! S-2.11: `ics.modbus_unit_id_sweep` — Modbus unit-ID discovery / recon detection.
//!
//! Fires when a single Modbus client issues requests to five or more distinct
//! unit IDs against the same server within a capture. This pattern is
//! characteristic of PLC discovery, automated fuzzing tools, and protocol
//! scanners enumerating the unit-ID space (0x00–0xFF). Severity escalates
//! from Medium (≥ 5 IDs) to High (≥ 50 IDs).
//!
//! See S-2.11 AC-002 (BC-3.03.006) for the full acceptance criteria.

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

/// Rule metadata for `ics.modbus_unit_id_sweep`.
///
/// GREEN-BY-DESIGN: pure `const` value initializer; zero branching, no I/O,
/// no non-trivial helper calls, ≤ 3 effective lines of payload.
pub const MODBUS_RECON_METADATA: RuleMetadata = RuleMetadata {
    id: "ics.modbus_unit_id_sweep",
    title: "Modbus unit-ID sweep — PLC discovery or fuzzing pattern",
    severity: Severity::Medium,
    trigger: "Fires when a single Modbus client (src IP) sends requests to five or \
              more distinct unit IDs addressed to the same server (dst IP) within the \
              capture window. The Modbus unit identifier (slave address, 0x00–0xFF) is \
              the primary way a master selects a specific PLC or slave device on a \
              shared serial segment. Sweeping a large range of unit IDs is a hallmark \
              of automated discovery tools, protocol fuzzers, and unauthorized \
              reconnaissance scripts. Severity is Medium for ≥ 5 distinct unit IDs and \
              escalates to High at ≥ 50. Evidence lists the (src, dst) pair, the total \
              count of distinct unit IDs observed, and the first ten unit IDs seen.",
    data_source: &["modbus_flow_summary"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0846 — Remote System Discovery",
            url: Some("https://attack.mitre.org/techniques/T0846/"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0888 — Remote System Information Discovery",
            url: Some("https://attack.mitre.org/techniques/T0888/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "Modbus Application Protocol Specification V1.1b3 §4.1 — Unit Identifier",
            url: Some("https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf"),
        },
    ],
};

/// Detect Modbus unit-ID sweep patterns (S-2.11, BC-3.03.006).
///
/// Returns one `Finding` per `(src, dst)` pair whose `unit_ids` set in
/// `Observations::modbus_flow_summary` reaches the Medium threshold (≥ 5).
/// Severity escalates to High at ≥ 50 distinct unit IDs.
pub fn build_findings(obs: &Observations) -> Vec<Finding> {
    const MEDIUM_THRESHOLD: usize = 5;
    const HIGH_THRESHOLD: usize = 50;

    let mut findings = Vec::new();

    for ((src, dst), summary) in &obs.modbus_flow_summary {
        let count = summary.unit_ids.len();
        if count < MEDIUM_THRESHOLD {
            continue;
        }

        let severity = if count >= HIGH_THRESHOLD {
            Severity::High
        } else {
            Severity::Medium
        };

        // Collect first 10 unit IDs (BTreeSet iterates in ascending order).
        let first_10: Vec<String> = summary
            .unit_ids
            .iter()
            .take(10)
            .map(|id| id.to_string())
            .collect();
        let extra = if count > 10 {
            format!(" (+{} more)", count - 10)
        } else {
            String::new()
        };
        let evidence_line = format!("{count} distinct unit IDs: {}{extra}", first_10.join(", "));

        let summary_text = format!(
            "Modbus client {} sent requests to {} distinct unit IDs addressed to server {} \
             within the capture. Sweeping the unit-ID space (0x00–0xFF) is a hallmark of \
             automated PLC discovery tools, protocol fuzzers, and unauthorized \
             reconnaissance scripts.",
            host_label(*src, obs),
            count,
            host_label(*dst, obs),
        );

        findings.push(Finding {
            id: "ics.modbus_unit_id_sweep",
            severity,
            title: format!(
                "Modbus unit-ID sweep from {} to {} ({} distinct IDs)",
                host_label(*src, obs),
                host_label(*dst, obs),
                count,
            ),
            summary: summary_text,
            evidence: vec![evidence_line],
            recommendation: "Investigate whether the source host is an authorized engineering \
                             workstation or SCADA system. Legitimate Modbus masters typically \
                             address a fixed set of known unit IDs. Restrict Modbus access to \
                             authorized hosts via network segmentation or firewall rules.",
            playbook: vec![
                format!(
                    "Identify the scanning host: {}. Check whether it is an authorized \
                     engineering workstation, SCADA server, or HMI. If unrecognized, treat \
                     as unauthorized reconnaissance.",
                    host_label(*src, obs)
                ),
                format!(
                    "Identify the targeted Modbus server: {}. Verify which unit IDs are \
                     legitimately configured on this device and compare against the observed \
                     sweep range.",
                    host_label(*dst, obs)
                ),
                "Review firewall and VLAN rules to ensure Modbus (tcp/502) is only \
                 accessible from authorized engineering hosts. Block or alert on connections \
                 from any host not in the approved list."
                    .to_string(),
                "If the source is an ICS asset (PLC, HMI), check for firmware compromise \
                 or misconfiguration. Unit-ID sweeps from trusted devices may indicate a \
                 supply-chain or insider threat."
                    .to_string(),
            ],
        });
    }

    findings
}
