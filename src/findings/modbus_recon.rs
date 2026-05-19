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

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

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
///
/// WIRING-EXEMPT stub: returns `Vec::new()` at stub stage. Wiring this
/// function into `findings::mod::run_all` (exercised by all snapshot tests)
/// before the implementation exists would cascade snapshot regressions — the
/// same lesson learned from S-2.05. The implementer promotes this to real
/// logic in Step 4.
pub fn build_findings(_obs: &Observations) -> Vec<Finding> {
    Vec::new()
}
