//! Integration tests for S-5.01 — policy digest (BC-1.05.003).
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use proptest::prelude::*;

use zonewarden_core::digest::compute;
use zonewarden_core::portset::PortSet;
use zonewarden_core::types::{
    AssetMatcher, Conduit, Direction, Policy, Proto, PurdueLevel, SlTarget, Zone, ZoneId,
};

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

fn zone(id: &str, members: &[&str], sl_t: Option<SlTarget>) -> Zone {
    Zone {
        id: ZoneId(id.to_string()),
        name: format!("{id} zone"),
        purdue_level: PurdueLevel::L2,
        sl_t,
        members: members.iter().map(|m| matcher(m)).collect(),
    }
}

fn cond(from: &str, to: &str, ports: PortSet) -> Conduit {
    Conduit {
        from_zone: ZoneId(from.to_string()),
        to_zone: ZoneId(to.to_string()),
        direction: Direction::Forward,
        proto: Proto::Tcp,
        ports,
    }
}

fn policy(zones: Vec<Zone>, conduits: Vec<Conduit>) -> Policy {
    Policy { zones, conduits }
}

fn ports(pairs: &[(u16, u16)]) -> PortSet {
    PortSet::from_pairs(pairs).unwrap()
}

// ── AC-001: structurally-equal policies → same digest ────────────────────────

// Phase 6 mutation-hardening: the digest must be SENSITIVE to every canonical
// token — two policies differing in exactly one field must hash differently.
// Replacing any digest token function with a constant collapses a distinction
// here (kills the digest.rs cargo-mutants survivors).
#[test]
fn test_BC_1_05_003_digest_sensitive_to_each_token() {
    let z0 = zone("z", &["10.0.0.0/24"], None);
    let z1 = zone("y", &["10.0.1.0/24"], None);
    let base_cond = cond("z", "y", ports(&[(502, 502)]));
    let d = compute(&policy(
        vec![z0.clone(), z1.clone()],
        vec![base_cond.clone()],
    ));

    let mut z = z0.clone();
    z.purdue_level = PurdueLevel::L4;
    assert_ne!(
        d,
        compute(&policy(vec![z, z1.clone()], vec![base_cond.clone()])),
        "digest must depend on purdue_level"
    );

    let mut z = z0.clone();
    z.sl_t = Some(SlTarget {
        overall: Some(3),
        fr_vector: None,
    });
    assert_ne!(
        d,
        compute(&policy(vec![z, z1.clone()], vec![base_cond.clone()])),
        "digest must depend on sl_t"
    );

    let mut c = base_cond.clone();
    c.direction = Direction::Bidirectional;
    assert_ne!(
        d,
        compute(&policy(vec![z0.clone(), z1.clone()], vec![c])),
        "digest must depend on direction"
    );

    let mut c = base_cond.clone();
    c.proto = Proto::Udp;
    assert_ne!(
        d,
        compute(&policy(vec![z0.clone(), z1.clone()], vec![c])),
        "digest must depend on proto"
    );

    let mut c = base_cond.clone();
    c.ports = ports(&[(44818, 44818)]);
    assert_ne!(
        d,
        compute(&policy(vec![z0.clone(), z1.clone()], vec![c])),
        "digest must depend on ports"
    );
}

#[test]
fn test_BC_1_05_003_structurally_equal_policies_same_digest() {
    // Same model: reversed zone order, reversed member order, and a duplicate
    // conduit (EC-002/EC-003/EC-005) — must hash identically.
    let a = policy(
        vec![
            zone("a", &["10.0.0.0/24", "10.0.0.5/32"], None),
            zone("b", &["10.0.1.0/24"], None),
        ],
        vec![cond("a", "b", PortSet::Any)],
    );
    let b = policy(
        vec![
            zone("b", &["10.0.1.0/24"], None),
            zone("a", &["10.0.0.5/32", "10.0.0.0/24"], None),
        ],
        vec![
            cond("a", "b", PortSet::Any),
            cond("a", "b", PortSet::Any), // duplicate → deduped
        ],
    );
    assert_eq!(compute(&a), compute(&b));
}

// ── AC-002: canonical order — zone/conduit reordering is invariant ───────────

#[test]
fn test_BC_1_05_003_canonical_sort_order() {
    let fwd = policy(
        vec![
            zone("a", &["10.0.0.0/24"], None),
            zone("b", &["10.0.1.0/24"], None),
        ],
        vec![
            cond("a", "b", PortSet::Any),
            cond("b", "a", ports(&[(502, 502)])),
        ],
    );
    let rev = policy(
        vec![
            zone("b", &["10.0.1.0/24"], None),
            zone("a", &["10.0.0.0/24"], None),
        ],
        vec![
            cond("b", "a", ports(&[(502, 502)])),
            cond("a", "b", PortSet::Any),
        ],
    );
    assert_eq!(compute(&fwd), compute(&rev));
}

// ── AC-003: zone members sorted ──────────────────────────────────────────────

#[test]
fn test_BC_1_05_003_zone_members_sorted() {
    let a = policy(
        vec![zone("a", &["10.0.0.5/32", "10.0.0.0/24"], None)],
        vec![],
    );
    let b = policy(
        vec![zone("a", &["10.0.0.0/24", "10.0.0.5/32"], None)],
        vec![],
    );
    assert_eq!(compute(&a), compute(&b));
}

// ── AC-004: PortSet is canonical in the digest ───────────────────────────────

#[test]
fn test_BC_1_05_003_portset_canonical_in_digest() {
    // [502, 500-502] canonicalizes to [500-502] at construction, so a conduit
    // built either way hashes the same.
    let a = policy(
        vec![],
        vec![cond("a", "b", ports(&[(502, 502), (500, 502)]))],
    );
    let b = policy(vec![], vec![cond("a", "b", ports(&[(500, 502)]))]);
    assert_eq!(compute(&a), compute(&b));
}

// ── AC-005: None fields omitted (and distinct from Some) ─────────────────────

#[test]
fn test_BC_1_05_003_none_fields_omitted() {
    let without = policy(vec![zone("a", &["10.0.0.0/24"], None)], vec![]);
    let with = policy(
        vec![zone(
            "a",
            &["10.0.0.0/24"],
            Some(SlTarget {
                overall: Some(3),
                fr_vector: None,
            }),
        )],
        vec![],
    );
    // An omitted sl_t is a distinct model state from a present one.
    assert_ne!(compute(&without), compute(&with));
    // ...and the omitted form is stable.
    assert_eq!(
        compute(&without),
        compute(&policy(vec![zone("a", &["10.0.0.0/24"], None)], vec![]))
    );
}

// ── AC-006: lowercase 64-hex format ──────────────────────────────────────────

#[test]
fn test_BC_1_05_003_digest_format_lowercase_hex() {
    let d = compute(&policy(
        vec![zone("a", &["10.0.0.0/24"], None)],
        vec![cond("a", "b", PortSet::Any)],
    ));
    assert_eq!(d.len(), 64, "digest: {d}");
    assert!(
        d.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "must be lowercase hex: {d}"
    );
}

// ── AC-007: different policies → different digests ───────────────────────────

#[test]
fn test_BC_1_05_003_different_policies_different_digests() {
    let base = policy(vec![zone("a", &["10.0.0.0/24"], None)], vec![]);
    let extra_zone = policy(
        vec![
            zone("a", &["10.0.0.0/24"], None),
            zone("b", &["10.0.1.0/24"], None),
        ],
        vec![],
    );
    let changed_cidr = policy(vec![zone("a", &["10.0.9.0/24"], None)], vec![]);
    assert_ne!(compute(&base), compute(&extra_zone));
    assert_ne!(compute(&base), compute(&changed_cidr));
    // A one-character name change also changes the digest (name is semantic).
    let mut renamed = base.clone();
    renamed.zones[0].name = "different".to_string();
    assert_ne!(compute(&base), compute(&renamed));
}

// ── EC-001: empty policy → deterministic digest ──────────────────────────────

#[test]
fn test_BC_1_05_003_empty_policy_deterministic() {
    let e = policy(vec![], vec![]);
    let d = compute(&e);
    assert_eq!(d.len(), 64);
    assert_eq!(d, compute(&policy(vec![], vec![])));
}

// ── Property (VP-1.05.003-a/b): order + duplicates do not change the digest ───

proptest! {
    #[test]
    fn test_BC_1_05_003_order_and_dupes_invariant(
        specs in prop::collection::vec((0u8..30, 0u8..255), 0..12)
    ) {
        // Build zones with unique ids (by index) and one member each.
        let zones_fwd: Vec<Zone> = specs.iter().enumerate()
            .map(|(i, (_, octet))| zone(&format!("z{i}"), &[&format!("10.0.{octet}.0/24")], None))
            .collect();
        let mut zones_rev = zones_fwd.clone();
        zones_rev.reverse();

        // One conduit per zone-pair-ish, plus a duplicate of the first.
        let mut conduits = vec![cond("z0", "EXTERNAL", PortSet::Any)];
        if !specs.is_empty() {
            conduits.push(cond("z0", "EXTERNAL", PortSet::Any)); // duplicate
        }
        let mut conduits_rev = conduits.clone();
        conduits_rev.reverse();

        let a = policy(zones_fwd, conduits);
        let b = policy(zones_rev, conduits_rev);
        prop_assert_eq!(compute(&a), compute(&b));
    }
}
