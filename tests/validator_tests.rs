//! Integration tests for S-1.03 — policy semantic validation
//! (BC-1.01.004 / 005 / 006 / 008).
//!
//! AC-005 (BC-1.01.007, invalid direction/proto token) is enforced at the load
//! boundary — a typed `Policy` cannot hold an invalid token — and is tested in
//! `zonewarden/tests/policy_load_tests.rs`.
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use zonewarden_core::errors::PolicyError;
use zonewarden_core::portset::PortSet;
use zonewarden_core::types::{
    AssetMatcher, Conduit, Direction, Policy, Proto, PurdueLevel, Zone, ZoneId,
};
use zonewarden_core::validator::validate;

// ── helpers ──────────────────────────────────────────────────────────────────

fn matcher(s: &str) -> AssetMatcher {
    match s.split_once('/') {
        Some((addr, plen)) => AssetMatcher::Cidr {
            addr: addr.parse().unwrap(),
            prefix_len: plen.parse().unwrap(),
        },
        None => AssetMatcher::Ip(s.parse().unwrap()),
    }
}

fn zone(id: &str, members: &[&str]) -> Zone {
    Zone {
        id: ZoneId(id.to_string()),
        name: id.to_string(),
        purdue_level: PurdueLevel::L2,
        sl_t: None,
        members: members.iter().map(|m| matcher(m)).collect(),
    }
}

fn conduit(from: &str, to: &str) -> Conduit {
    Conduit {
        from_zone: ZoneId(from.to_string()),
        to_zone: ZoneId(to.to_string()),
        direction: Direction::Forward,
        proto: Proto::Tcp,
        ports: PortSet::Any,
    }
}

fn policy(zones: Vec<Zone>, conduits: Vec<Conduit>) -> Policy {
    Policy { zones, conduits }
}

// ── AC-001: duplicate zone id → E-POL-005 ────────────────────────────────────

#[test]
fn test_BC_1_01_004_duplicate_zone_id_rejected() {
    let p = policy(
        vec![
            zone("field", &["10.0.1.0/24"]),
            zone("field", &["10.0.2.0/24"]),
        ],
        vec![],
    );
    match validate(p) {
        Err(PolicyError::DuplicateZoneId { id }) => assert_eq!(id, "field"),
        other => panic!("expected E-POL-005, got {other:?}"),
    }
}

// ── AC-007: reserved EXTERNAL id → E-POL-005 ─────────────────────────────────

#[test]
fn test_BC_1_01_004_external_reserved_id_rejected() {
    let p = policy(vec![zone("EXTERNAL", &["10.0.1.0/24"])], vec![]);
    match validate(p) {
        Err(PolicyError::DuplicateZoneId { id }) => assert_eq!(id, "EXTERNAL"),
        other => panic!("expected E-POL-005 for reserved id, got {other:?}"),
    }
}

// ── AC-002: conduit referencing unknown zone → E-POL-006 ─────────────────────

#[test]
fn test_BC_1_01_004_conduit_unknown_zone_rejected() {
    let p = policy(
        vec![zone("field", &["10.0.1.0/24"])],
        vec![conduit("field", "ghost")],
    );
    match validate(p) {
        Err(PolicyError::UnknownConduitZone { zone, .. }) => assert_eq!(zone, "ghost"),
        other => panic!("expected E-POL-006, got {other:?}"),
    }
}

#[test]
fn test_BC_1_01_004_external_conduit_endpoint_ok() {
    // EC-001/EC-002/EC-003: EXTERNAL is always a legal conduit endpoint.
    let p = policy(
        vec![zone("field", &["10.0.1.0/24"])],
        vec![conduit("EXTERNAL", "field"), conduit("field", "EXTERNAL")],
    );
    assert!(validate(p).is_ok());
}

// ── AC-003: equal-prefix tie → E-POL-007; disjoint / different-len → OK ───────

#[test]
fn test_BC_1_01_005_equal_prefix_tie_rejected() {
    let p = policy(
        vec![zone("a", &["10.0.1.0/24"]), zone("b", &["10.0.1.0/24"])],
        vec![],
    );
    match validate(p) {
        Err(PolicyError::PrefixTie {
            cidr,
            zone_a,
            zone_b,
        }) => {
            assert!(cidr.contains("10.0.1.0"), "cidr was {cidr}");
            let zones = [zone_a, zone_b];
            assert!(zones.contains(&"a".to_string()) && zones.contains(&"b".to_string()));
        }
        other => panic!("expected E-POL-007, got {other:?}"),
    }
}

#[test]
fn test_BC_1_01_005_host_tie_rejected() {
    // EC-004: identical /32 hosts in two zones tie.
    let p = policy(
        vec![zone("a", &["10.0.0.5/32"]), zone("b", &["10.0.0.5/32"])],
        vec![],
    );
    assert!(matches!(validate(p), Err(PolicyError::PrefixTie { .. })));
}

#[test]
fn test_BC_1_01_005_ipv4_mapped_member_ties_with_ipv4() {
    // EC-005: ::ffff:10.0.0.0/120 canonicalizes to IPv4 10.0.0.0/24 and ties
    // with a literal IPv4 10.0.0.0/24 in another zone (WAVE3-002 fix).
    let p = policy(
        vec![
            zone("a", &["10.0.0.0/24"]),
            zone("b", &["::ffff:10.0.0.0/120"]),
        ],
        vec![],
    );
    assert!(
        matches!(validate(p), Err(PolicyError::PrefixTie { .. })),
        "IPv4-mapped IPv6 member must canonicalize to IPv4 and tie"
    );
}

#[test]
fn test_BC_1_01_005_disjoint_same_length_ok() {
    // EC-002: disjoint same-length CIDRs are not a tie (DEC-022).
    let p = policy(
        vec![zone("a", &["10.0.0.0/24"]), zone("b", &["10.0.1.0/24"])],
        vec![],
    );
    assert!(validate(p).is_ok());
}

#[test]
fn test_BC_1_01_005_different_prefix_length_ok() {
    // EC-003: a /32 and an enclosing /24 in different zones resolve by longest
    // prefix; not a tie.
    let p = policy(
        vec![zone("a", &["10.0.0.5/32"]), zone("b", &["10.0.0.0/24"])],
        vec![],
    );
    assert!(validate(p).is_ok());
}

#[test]
fn test_BC_1_01_005_same_zone_duplicate_member_is_not_a_tie() {
    // A redundant member within one zone is not ambiguous (cross-zone only).
    let p = policy(vec![zone("a", &["10.0.1.0/24", "10.0.1.0/24"])], vec![]);
    assert!(validate(p).is_ok());
}

// ── AC-004: /0 catch-all member → E-POL-008 ──────────────────────────────────

#[test]
fn test_BC_1_01_006_catch_all_cidr_rejected() {
    let p = policy(vec![zone("field", &["0.0.0.0/0"])], vec![]);
    match validate(p) {
        Err(PolicyError::CatchAllPrefix { zone, cidr }) => {
            assert_eq!(zone, "field");
            assert!(cidr.contains("0.0.0.0/0"), "cidr was {cidr}");
        }
        other => panic!("expected E-POL-008, got {other:?}"),
    }
}

#[test]
fn test_BC_1_01_006_ipv6_catch_all_rejected() {
    let p = policy(vec![zone("field", &["::/0"])], vec![]);
    assert!(matches!(
        validate(p),
        Err(PolicyError::CatchAllPrefix { .. })
    ));
}

// ── AC-006: zero-member zone → OK + warning ──────────────────────────────────

#[test]
fn test_BC_1_01_008_zero_members_warn_not_error() {
    let p = policy(vec![zone("field", &[])], vec![]);
    let vp = validate(p).expect("zero-member zone is valid");
    assert!(
        vp.warnings
            .iter()
            .any(|w| w.contains("has no members") && w.contains("field")),
        "warnings: {:?}",
        vp.warnings
    );
}

// ── AC-008: very short prefix (< /8) → OK + warning (OQ-004) ──────────────────

#[test]
fn test_BC_1_01_004_short_prefix_warning_emitted() {
    let p = policy(vec![zone("field", &["10.0.0.0/7"])], vec![]);
    let vp = validate(p).expect("short prefix is valid (warn only)");
    assert!(
        vp.warnings
            .iter()
            .any(|w| w.contains("short prefix") && w.contains("field")),
        "warnings: {:?}",
        vp.warnings
    );
}

#[test]
fn test_BC_1_01_006_prefix_one_through_seven_not_error() {
    // EC-003 of BC-1.01.006: /1 is legal (warning, not error).
    let p = policy(vec![zone("field", &["0.0.0.0/1"])], vec![]);
    assert!(validate(p).is_ok());
}

// ── AC-009: ValidatedPolicy carries the descending-sorted prefix index ───────

#[test]
fn test_BC_1_01_004_validated_policy_contains_sorted_index() {
    let p = policy(
        vec![
            zone("big", &["10.0.0.0/16"]),
            zone("small", &["10.0.0.5/32", "10.1.0.0/24"]),
        ],
        vec![],
    );
    let vp = validate(p).expect("valid policy");
    let lens: Vec<u8> = vp
        .prefix_index
        .iter()
        .map(|(net, _)| net.prefix_len())
        .collect();
    assert_eq!(
        lens,
        vec![32, 24, 16],
        "index must be sorted descending by prefix_len"
    );
    // every member is indexed
    assert_eq!(vp.prefix_index.len(), 3);
}

// ── happy-path + vacuous-valid edge cases ────────────────────────────────────

#[test]
fn test_BC_1_01_004_valid_policy_passes_no_warnings() {
    let p = policy(
        vec![
            zone("plc", &["10.0.1.0/24"]),
            zone("hist", &["10.0.3.5/32"]),
        ],
        vec![conduit("plc", "hist")],
    );
    let vp = validate(p).expect("valid");
    assert!(vp.warnings.is_empty(), "warnings: {:?}", vp.warnings);
}

#[test]
fn test_empty_policy_is_vacuously_valid() {
    // EC-009/EC-010: no zones (and no conduits) is valid; deny-all.
    assert!(validate(policy(vec![], vec![])).is_ok());
}
