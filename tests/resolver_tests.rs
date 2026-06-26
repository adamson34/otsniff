//! Integration tests for S-3.01 — zone resolver (BC-1.03.001 / 002 / 005).
//!
//! The index is built through the real validator (S-1.03) so the resolver is
//! tested against genuine validator output (sorted, tie-free).
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use std::net::IpAddr;

use proptest::prelude::*;

use zonewarden_core::resolver::{resolve, resolve_pair};
use zonewarden_core::types::{
    AssetMatcher, MatchKind, Policy, PrefixIndex, PurdueLevel, Zone, ZoneId,
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

/// Build a resolver index from `(zone_id, members)` specs via the validator.
fn index_for(specs: &[(&str, &[&str])]) -> PrefixIndex {
    let zones = specs.iter().map(|(id, m)| zone(id, m)).collect();
    validate(Policy {
        zones,
        conduits: vec![],
    })
    .expect("valid policy")
    .prefix_index
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ── AC-001 / EC-001: longest prefix wins ─────────────────────────────────────

#[test]
fn test_BC_1_03_001_longest_prefix_wins() {
    let idx = index_for(&[("a", &["10.0.0.0/16"]), ("b", &["10.0.1.0/24"])]);
    let r = resolve(&idx, ip("10.0.1.5"));
    assert_eq!(r.zone_id, ZoneId("b".to_string()));
    assert_eq!(r.match_kind, MatchKind::Explicit { prefix_len: 24 });
}

// ── AC-003 / EC-002: /32 host wins over /24 net ──────────────────────────────

#[test]
fn test_BC_1_03_001_host_32_wins_over_net_24() {
    let idx = index_for(&[("a", &["10.0.0.5/32"]), ("b", &["10.0.0.0/24"])]);
    let r = resolve(&idx, ip("10.0.0.5"));
    assert_eq!(r.zone_id, ZoneId("a".to_string()));
    assert_eq!(r.match_kind, MatchKind::Explicit { prefix_len: 32 });
}

// ── AC-008 / EC-007: network address resolves normally (OQ-005) ──────────────

#[test]
fn test_BC_1_03_001_network_address_resolves_normally() {
    let idx = index_for(&[("a", &["10.0.0.0/24"])]);
    let r = resolve(&idx, ip("10.0.0.0"));
    assert_eq!(r.zone_id, ZoneId("a".to_string()));
    assert_eq!(r.match_kind, MatchKind::Explicit { prefix_len: 24 });
}

// ── EC-005: /8 zone matches; only /0 is rejected ─────────────────────────────

#[test]
fn test_BC_1_03_001_slash8_matches() {
    let idx = index_for(&[("a", &["0.0.0.0/8"])]);
    let r = resolve(&idx, ip("0.0.0.1"));
    assert_eq!(r.zone_id, ZoneId("a".to_string()));
    assert_eq!(r.match_kind, MatchKind::Explicit { prefix_len: 8 });
}

// ── AC-004 / BC-1.03.002: unmatched → implicit EXTERNAL ──────────────────────

#[test]
fn test_BC_1_03_002_unmatched_resolves_to_external() {
    let idx = index_for(&[("a", &["10.0.0.0/24"])]);
    let r = resolve(&idx, ip("192.168.1.5"));
    assert!(r.zone_id.is_external());
    assert_eq!(r.match_kind, MatchKind::ImplicitExternal);
}

// ── EC-006: IPv6 endpoint, IPv4-only policy → EXTERNAL ────────────────────────

#[test]
fn test_BC_1_03_002_ipv6_endpoint_ipv4_policy_is_external() {
    let idx = index_for(&[("a", &["10.0.0.0/24"])]);
    let r = resolve(&idx, ip("2001:db8::1"));
    assert!(r.zone_id.is_external());
    assert_eq!(r.match_kind, MatchKind::ImplicitExternal);
}

// ── AC-005 / BC-1.03.005: both endpoints EXTERNAL → same zone (→ IntraZone) ───

#[test]
fn test_BC_1_03_005_both_external_yields_intra_zone() {
    let idx = index_for(&[("a", &["10.0.1.0/24"])]);
    let pair = resolve_pair(&idx, ip("8.8.8.8"), ip("1.1.1.1"));
    assert!(pair.both_external());
    assert!(
        pair.same_zone(),
        "both EXTERNAL is the same-zone predicate (→ IntraZone)"
    );
    assert_eq!(pair.src.match_kind, MatchKind::ImplicitExternal);
    assert_eq!(pair.dst.match_kind, MatchKind::ImplicitExternal);
}

// ── EC-002 of BC-1.03.005: one EXTERNAL, one declared → NOT both-external ─────

#[test]
fn test_BC_1_03_005_one_external_is_cross_zone() {
    let idx = index_for(&[("a", &["10.0.1.0/24"])]);
    let pair = resolve_pair(&idx, ip("10.0.1.5"), ip("8.8.8.8"));
    assert!(!pair.both_external());
    assert!(!pair.same_zone());
    assert_eq!(pair.src.zone_id, ZoneId("a".to_string()));
    assert!(pair.dst.zone_id.is_external());
}

// ── AC-002 / AC-006: deterministic + total (never panics) over arbitrary IPs ──

proptest! {
    #[test]
    fn test_BC_1_03_001_resolution_deterministic_and_total(octets in any::<[u8; 4]>()) {
        let idx = index_for(&[("a", &["10.0.0.0/16"]), ("b", &["10.0.1.0/24"])]);
        let addr = IpAddr::from(octets);
        let first = resolve(&idx, addr);
        let second = resolve(&idx, addr);
        // deterministic
        prop_assert_eq!(&first, &second);
        // total: always produced a resolution (the type guarantees it; this also
        // proves no panic for any input)
        let resolved = first.zone_id.is_external()
            || matches!(first.match_kind, MatchKind::Explicit { .. });
        prop_assert!(resolved);
    }
}
