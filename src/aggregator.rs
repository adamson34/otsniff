//! Aggregator — assemble per-flow verdicts into a `ConformanceResult` (pure
//! core, S-5.02, ST-7).
//!
//! Accumulates each `(Verdict, Vec<Violation>)` (the classifier's per-flow
//! output) into the run tally with **checked** `u64` arithmetic (BC-1.05.004,
//! FM-009): any increment that would exceed `u64::MAX` aborts with
//! [`SysError::TallyOverflow`] rather than wrapping. The five verdict-kind tallies
//! satisfy the DI-015 accounting identity by construction:
//! `total_flows == intra_zone + allowed + no_matching_conduit + wrong_direction
//! plus multicast_exempt` (BC-1.05.001). `idmz_bypasses` and `external_endpoints`
//! are additive diagnostics outside the identity; `distinct_violating_flows` is
//! the count of distinct flow indices with ≥1 violation. `skipped` is passed in
//! (never computed here) and is excluded from `total_flows`. Empty input yields
//! an all-zero result (BC-1.05.005). `violations` are collected unsorted — the
//! deterministic sort is S-5.03.

use std::collections::HashSet;

use crate::digest;
use crate::errors::SysError;
use crate::types::{ConformanceResult, ValidatedPolicy, Verdict, VerdictKind, Violation};

/// Increment a `u64` tally by one, aborting on overflow (BC-1.05.004 / FM-009).
pub fn checked_inc(n: u64) -> Result<u64, SysError> {
    n.checked_add(1).ok_or(SysError::TallyOverflow)
}

/// Aggregate classified flows into a `ConformanceResult` (BC-1.05.001/004/005).
pub fn aggregate(
    items: impl IntoIterator<Item = (Verdict, Vec<Violation>)>,
    policy: &ValidatedPolicy,
    skipped: u64,
    warnings: Vec<String>,
) -> Result<ConformanceResult, SysError> {
    let mut r = ConformanceResult {
        skipped,
        warnings,
        ..Default::default()
    };
    // distinct flow indices with ≥1 violation (dedup; BC-1.05.001).
    let mut violating: HashSet<u64> = HashSet::new();

    for (verdict, violations) in items {
        r.total_flows = checked_inc(r.total_flows)?;

        // Exactly one kind tally per flow → the DI-015 identity holds by
        // construction (BC-1.05.001 postcondition 1).
        match verdict.kind {
            VerdictKind::IntraZone => r.intra_zone = checked_inc(r.intra_zone)?,
            VerdictKind::Allowed(_) => r.allowed = checked_inc(r.allowed)?,
            VerdictKind::NoMatchingConduit => {
                r.no_matching_conduit = checked_inc(r.no_matching_conduit)?
            }
            VerdictKind::WrongDirection => r.wrong_direction = checked_inc(r.wrong_direction)?,
            VerdictKind::MulticastExempt => r.multicast_exempt = checked_inc(r.multicast_exempt)?,
        }

        // Additive diagnostics, outside the identity (BC-1.05.001 inv 2 / DEC-026).
        if verdict.idmz_bypass {
            r.idmz_bypasses = checked_inc(r.idmz_bypasses)?;
        }
        if verdict.src_zone.is_external() || verdict.dst_zone.is_external() {
            r.external_endpoints = checked_inc(r.external_endpoints)?;
        }

        // A flow is violating iff it carries a conduit violation or an IDMZ
        // bypass; count its flow_index once (BC-1.04.007 PC5).
        let is_violating = matches!(
            verdict.kind,
            VerdictKind::NoMatchingConduit | VerdictKind::WrongDirection
        ) || verdict.idmz_bypass;
        if is_violating {
            violating.insert(verdict.flow_index);
        }

        r.violations.extend(violations);
    }

    r.distinct_violating_flows = violating.len() as u64;

    // Deterministic total-order sort (BC-1.05.002 / DI-009): identical input →
    // byte-identical output. `flow_index` is the final tiebreaker (unique per
    // run), so the order is strict and stable regardless of insertion order.
    r.violations.sort_by_key(|v| {
        (
            v.ts,
            v.src_ip,
            v.src_port,
            v.dst_ip,
            v.dst_port,
            v.proto.clone(),
            v.flow_index,
        )
    });

    r.policy_digest = digest::compute(&policy.policy);
    Ok(r)
}
