//! IDMZ no-bypass check (pure core, S-4.02).
//!
//! Implements the Purdue 3.5 Industrial-DMZ rule (DI-006): a direct flow between
//! an OT-side zone (≤ L3) and an IT-side zone (≥ L4) that does not route through
//! the IDMZ (L3.5) is a bypass — the headline IEC 62443 control.
//!
//! `idmz_bypass` is an **additive** finding (BC-1.04.007): it is computed
//! independently of the conduit `VerdictKind` (a flow can be both `Allowed` and a
//! bypass), so [`check`] takes no verdict. Exclusions (BC-1.04.008): a
//! `MulticastBroadcast` dst, or either endpoint resolving to the reserved
//! EXTERNAL zone, force `false`. EXTERNAL is excluded by zone *identity*, never
//! by its sentinel purdue level. IDMZ endpoints fall out naturally: `is_ot`/
//! `is_it` both exclude L3.5, so any flow touching the IDMZ is not a bypass.

use crate::types::{DstKind, PurdueLevel, ResolvedEndpoint, ValidatedPolicy, ZoneId};

/// Whether a resolved flow is a direct OT↔IT IDMZ bypass (DI-006 truth table).
pub fn check(
    src: &ResolvedEndpoint,
    dst: &ResolvedEndpoint,
    dst_kind: DstKind,
    policy: &ValidatedPolicy,
) -> bool {
    // Exclusions (BC-1.04.008): multicast dst, or either endpoint EXTERNAL
    // (by zone identity, never by purdue level).
    if dst_kind == DstKind::MulticastBroadcast {
        return false;
    }
    if src.zone_id.is_external() || dst.zone_id.is_external() {
        return false;
    }
    // Both endpoints are managed zones — look up their Purdue levels.
    let (Some(s), Some(d)) = (
        level_of(policy, &src.zone_id),
        level_of(policy, &dst.zone_id),
    ) else {
        return false;
    };
    bypass_predicate(s, d)
}

/// The DI-006 OT↔IT predicate: a bypass iff one side is OT (≤L3) and the other
/// is IT (≥L4). `is_ot`/`is_it` both exclude the IDMZ (L3.5), so any flow
/// touching the IDMZ — or with both endpoints on the same side — yields `false`.
fn bypass_predicate(s: PurdueLevel, d: PurdueLevel) -> bool {
    (s.is_ot() && d.is_it()) || (s.is_it() && d.is_ot())
}

/// Look up a managed zone's Purdue level by id. EXTERNAL is never looked up here
/// (it is excluded before this point and is not a declared zone).
fn level_of(policy: &ValidatedPolicy, zone_id: &ZoneId) -> Option<PurdueLevel> {
    policy
        .policy
        .zones
        .iter()
        .find(|z| &z.id == zone_id)
        .map(|z| z.purdue_level)
}

/// Formal-verification harness (VP-1.04.007-a). Compiled only under `cargo kani`.
#[cfg(kani)]
mod kani_harness {
    use super::*;

    fn level(i: u8) -> PurdueLevel {
        match i % 7 {
            0 => PurdueLevel::L0,
            1 => PurdueLevel::L1,
            2 => PurdueLevel::L2,
            3 => PurdueLevel::L3,
            4 => PurdueLevel::Idmz,
            5 => PurdueLevel::L4,
            _ => PurdueLevel::L5,
        }
    }

    /// The bypass predicate is exactly the DI-006 truth table over all 7×7 level
    /// pairs: IDMZ-touching → false; same-side → false; cross-side → true.
    #[kani::proof]
    fn bypass_truth_table() {
        let s = level(kani::any());
        let d = level(kani::any());
        let b = bypass_predicate(s, d);

        if matches!(s, PurdueLevel::Idmz) || matches!(d, PurdueLevel::Idmz) {
            assert!(!b, "IDMZ endpoint is never a bypass");
        } else if s.is_ot() && d.is_ot() {
            assert!(!b, "both OT is not a bypass");
        } else if s.is_it() && d.is_it() {
            assert!(!b, "both IT is not a bypass");
        } else {
            assert!(b, "cross OT/IT is a bypass");
        }
    }
}
