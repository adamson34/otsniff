//! Cross-capture diff core (P1-3, S-6.02).
//!
//! Computes the delta between two captures using their merged ScrubMaps
//! (S-6.01) so identification is by pseudonym, not raw IP. Output is a
//! pure-data `Diff` struct; rendering lives in S-6.03.

use crate::findings::Finding;
use crate::inventory::Asset;
use crate::observe::Observations;
use crate::scrub::ScrubMap;
use serde::Serialize;

/// Role inference result for a host. Mirror the shape used by inventory.
/// (If `inventory::Role` already exists, alias it here instead of redefining.)
pub type Role = String; // TODO(S-6.02 step 4): replace with crate::inventory::Role if it exists

/// A change in a host's inferred role between the baseline and current capture.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RoleShift {
    pub pseudonym: String,
    pub old_role: Role,
    pub new_role: Role,
}

/// A change in a single flow's traffic shape between baseline and current.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowDelta {
    pub src: String,
    pub dst: String,
    pub dst_port: u16,
    pub proto: String,
    /// Baseline byte count; None means the flow did not exist in baseline.
    pub baseline_bytes: Option<u64>,
    /// Current byte count; None means the flow disappeared in current.
    pub current_bytes: Option<u64>,
}

/// Top-level diff output. Pure data; renderer (S-6.03) consumes this.
///
/// Note: `Deserialize` is intentionally omitted — `Finding` contains
/// `&'static str` fields that do not implement `Deserialize`. The implementer
/// should address round-trip serialization in S-6.03 if needed.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Diff {
    pub hosts_new: Vec<Asset>,
    pub hosts_gone: Vec<Asset>,
    pub findings_new: Vec<Finding>,
    pub findings_recurring: Vec<Finding>,
    pub findings_resolved: Vec<Finding>,
    pub role_shifts: Vec<RoleShift>,
    pub flow_shifts: Vec<FlowDelta>,
}

/// Inputs to `compute`: each side carries its own observations + merged map.
pub struct DiffInput<'a> {
    pub observations: &'a Observations,
    pub map: &'a ScrubMap,
}

/// Compute the delta between two captures.
///
/// **AC-002 (BC-3.08.001):** identifies hosts by pseudonym, not raw IP.
/// **AC-003 (BC-3.08.002):** matches findings on `(rule_id, src_pseudo, dst_pseudo, dst_port)`.
/// **AC-004 (BC-3.08.003):** detects role inference changes and 2×-default flow-volume shifts.
pub fn compute(_baseline: DiffInput<'_>, _current: DiffInput<'_>) -> Diff {
    todo!("S-6.02 step 4: implement diff computation per AC-002..004")
}

/// Configurable threshold for the flow-shift detector (AC-004). Default 2×.
pub const DEFAULT_FLOW_SHIFT_MULTIPLIER: f64 = 2.0;
