//! Integration tests for S-4.02 — IDMZ no-bypass truth table (BC-1.04.007/008).
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use std::net::IpAddr;

use zonewarden_core::idmz::check;
use zonewarden_core::types::{
    AssetMatcher, DstKind, MatchKind, Policy, PurdueLevel, ResolvedEndpoint, ValidatedPolicy, Zone,
    ZoneId,
};
use zonewarden_core::validator::validate;

// ── helpers ──────────────────────────────────────────────────────────────────

/// A validated policy with one zone per Purdue level. Members are disjoint /24s
/// so there are no ties. Zone ids match their level for readability.
fn policy() -> ValidatedPolicy {
    let specs: &[(&str, PurdueLevel, &str)] = &[
        ("l0", PurdueLevel::L0, "10.0.0.0/24"),
        ("l1", PurdueLevel::L1, "10.0.1.0/24"),
        ("l2", PurdueLevel::L2, "10.0.2.0/24"),
        ("l3", PurdueLevel::L3, "10.0.3.0/24"),
        ("dmz", PurdueLevel::Idmz, "10.0.4.0/24"),
        ("l4", PurdueLevel::L4, "10.0.5.0/24"),
        ("l5", PurdueLevel::L5, "10.0.6.0/24"),
    ];
    let zones = specs
        .iter()
        .map(|(id, level, cidr)| {
            let (addr, plen) = cidr.split_once('/').unwrap();
            Zone {
                id: ZoneId(id.to_string()),
                name: id.to_string(),
                purdue_level: *level,
                sl_t: None,
                members: vec![AssetMatcher::Cidr {
                    addr: addr.parse().unwrap(),
                    prefix_len: plen.parse().unwrap(),
                }],
            }
        })
        .collect();
    validate(Policy {
        zones,
        conduits: vec![],
    })
    .expect("valid policy")
}

fn ep(zone_id: &str) -> ResolvedEndpoint {
    let dummy: IpAddr = "10.0.0.1".parse().unwrap();
    let match_kind = if zone_id == ZoneId::EXTERNAL {
        MatchKind::ImplicitExternal
    } else {
        MatchKind::Explicit { prefix_len: 24 }
    };
    ResolvedEndpoint {
        ip: dummy,
        zone_id: ZoneId(zone_id.to_string()),
        match_kind,
    }
}

// ── AC-001: OT (≤L3) ↔ IT (≥L4) → bypass ─────────────────────────────────────

#[test]
fn test_BC_1_04_007_ot_to_it_triggers_bypass() {
    let p = policy();
    assert!(check(&ep("l2"), &ep("l4"), DstKind::Normal, &p));
    // reverse direction (IT → OT) is symmetric
    assert!(check(&ep("l4"), &ep("l2"), DstKind::Normal, &p));
}

// ── AC-002: additive — independent of any conduit verdict (no verdict param) ──

#[test]
fn test_BC_1_04_007_bypass_additive_to_conduit_verdict() {
    let p = policy();
    // The check has no VerdictKind input; an L1→L4 flow that a conduit might
    // ALLOW is still reported as a bypass (additive finding).
    assert!(check(&ep("l1"), &ep("l4"), DstKind::Normal, &p));
}

// ── AC-007: same side → no bypass ────────────────────────────────────────────

#[test]
fn test_BC_1_04_007_same_side_no_bypass() {
    let p = policy();
    assert!(!check(&ep("l2"), &ep("l3"), DstKind::Normal, &p)); // both ≤L3
    assert!(!check(&ep("l4"), &ep("l5"), DstKind::Normal, &p)); // both ≥L4
}

// ── AC-005: IDMZ endpoint → no bypass ────────────────────────────────────────

#[test]
fn test_BC_1_04_007_idmz_endpoint_no_bypass() {
    let p = policy();
    assert!(!check(&ep("l2"), &ep("dmz"), DstKind::Normal, &p));
    assert!(!check(&ep("dmz"), &ep("l4"), DstKind::Normal, &p));
}

// ── AC-006 / AC-008: declared L5 is managed; exclusion is by EXTERNAL identity ─

#[test]
fn test_BC_1_04_007_declared_l5_is_managed() {
    let p = policy();
    // declared L5 zone (not EXTERNAL) is a ≥L4 endpoint → bypass with L1
    assert!(check(&ep("l1"), &ep("l5"), DstKind::Normal, &p));
}

#[test]
fn test_BC_1_04_007_external_exclusion_by_identity_not_level() {
    let p = policy();
    // declared L5 → NOT excluded (bypass true); EXTERNAL → excluded (false).
    assert!(check(&ep("l1"), &ep("l5"), DstKind::Normal, &p));
    assert!(!check(
        &ep("l1"),
        &ep(ZoneId::EXTERNAL),
        DstKind::Normal,
        &p
    ));
}

// ── AC-003: EXTERNAL endpoint → no bypass ────────────────────────────────────

#[test]
fn test_BC_1_04_008_external_endpoint_no_bypass() {
    let p = policy();
    assert!(!check(
        &ep("l1"),
        &ep(ZoneId::EXTERNAL),
        DstKind::Normal,
        &p
    ));
    assert!(!check(
        &ep(ZoneId::EXTERNAL),
        &ep("l4"),
        DstKind::Normal,
        &p
    ));
}

// ── BC-1.04.008: EXTERNAL excluded by identity, BEFORE any level lookup ───────
// The exclusion guard is `src.is_external() || dst.is_external()` — EITHER side
// external forces `false`, and it short-circuits before levels are resolved
// (module doc: "EXTERNAL is excluded by zone identity, never by its level").
// To prove the guard is an OR (not an AND) AND that it precedes level lookup, we
// pathologically declare the reserved EXTERNAL id as a managed L5/IT zone: a
// single-external OT↔EXTERNAL pair must STILL be excluded. With `||`→`&&` the
// guard would not fire (only one side external) and the level lookup would
// misreport an L1↔L5 bypass.
#[test]
fn test_BC_1_04_008_external_excluded_before_level_lookup() {
    let ot = Zone {
        id: ZoneId("l1".into()),
        name: "l1".into(),
        purdue_level: PurdueLevel::L1,
        sl_t: None,
        members: vec![AssetMatcher::Cidr {
            addr: "10.0.1.0".parse().unwrap(),
            prefix_len: 24,
        }],
    };
    let ext = Zone {
        id: ZoneId(ZoneId::EXTERNAL.to_string()),
        name: "ext".into(),
        purdue_level: PurdueLevel::L5, // pathological: EXTERNAL with an IT level
        sl_t: None,
        members: vec![AssetMatcher::Cidr {
            addr: "203.0.113.0".parse().unwrap(),
            prefix_len: 24,
        }],
    };
    let p = ValidatedPolicy {
        policy: Policy {
            zones: vec![ot, ext],
            conduits: vec![],
        },
        prefix_index: Vec::new(),
        warnings: Vec::new(),
    };
    // Either ordering of the single-external pair → excluded (false).
    assert!(!check(
        &ep("l1"),
        &ep(ZoneId::EXTERNAL),
        DstKind::Normal,
        &p
    ));
    assert!(!check(
        &ep(ZoneId::EXTERNAL),
        &ep("l1"),
        DstKind::Normal,
        &p
    ));
}

// ── AC-004: MulticastBroadcast dst → no bypass ───────────────────────────────

#[test]
fn test_BC_1_04_008_multicast_dst_no_bypass() {
    let p = policy();
    // would be a bypass on Normal, but MulticastBroadcast forces false (DI-016).
    assert!(check(&ep("l1"), &ep("l4"), DstKind::Normal, &p));
    assert!(!check(
        &ep("l1"),
        &ep("l4"),
        DstKind::MulticastBroadcast,
        &p
    ));
}
