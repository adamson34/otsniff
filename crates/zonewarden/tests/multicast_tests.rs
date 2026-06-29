//! Integration tests for S-3.02 — multicast / directed-broadcast detection
//! (BC-1.03.003 / 004).
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;

use zonewarden_core::multicast::classify_dst;
use zonewarden_core::types::{
    AssetMatcher, DstKind, Policy, PrefixIndex, PurdueLevel, Zone, ZoneId,
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

fn index_for(specs: &[(&str, &[&str])]) -> PrefixIndex {
    let zones = specs
        .iter()
        .map(|(id, m)| Zone {
            id: ZoneId(id.to_string()),
            name: id.to_string(),
            purdue_level: PurdueLevel::L2,
            sl_t: None,
            members: m.iter().map(|x| matcher(x)).collect(),
        })
        .collect();
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

// ── AC-001/002/003: Step-1 family-wide multicast/broadcast (no zone needed) ───

#[test]
fn test_BC_1_03_003_ipv4_multicast_range_detected() {
    let idx = index_for(&[]);
    assert_eq!(
        classify_dst(ip("224.0.0.1"), &idx),
        DstKind::MulticastBroadcast
    );
    assert_eq!(
        classify_dst(ip("239.255.255.250"), &idx),
        DstKind::MulticastBroadcast
    );
    // EC-005: just below the multicast range is NOT multicast.
    assert_eq!(classify_dst(ip("223.255.255.255"), &idx), DstKind::Normal);
}

#[test]
fn test_BC_1_03_003_ipv4_limited_broadcast_detected() {
    let idx = index_for(&[]);
    assert_eq!(
        classify_dst(ip("255.255.255.255"), &idx),
        DstKind::MulticastBroadcast
    );
}

#[test]
fn test_BC_1_03_003_ipv6_multicast_range_detected() {
    let idx = index_for(&[]);
    assert_eq!(
        classify_dst(ip("ff02::1"), &idx),
        DstKind::MulticastBroadcast
    );
    assert_eq!(
        classify_dst(ip("ff00::abcd"), &idx),
        DstKind::MulticastBroadcast
    );
    // a normal global IPv6 is not multicast
    assert_eq!(classify_dst(ip("2001:db8::1"), &idx), DstKind::Normal);
}

// ── AC-006: Step-1 fires before zone matching (multicast in a declared zone) ──

#[test]
fn test_BC_1_03_003_multicast_in_zone_cidr_still_exempt() {
    // A zone that declares the multicast range; Step-1 still wins.
    let idx = index_for(&[("mc", &["224.0.0.0/4"])]);
    assert_eq!(
        classify_dst(ip("224.0.0.100"), &idx),
        DstKind::MulticastBroadcast
    );
}

// ── AC-004: directed broadcast of a ≤/30 zone CIDR ───────────────────────────

#[test]
fn test_BC_1_03_004_directed_broadcast_detected_le30() {
    let idx = index_for(&[("a", &["10.0.1.0/24"])]);
    assert_eq!(
        classify_dst(ip("10.0.1.255"), &idx),
        DstKind::MulticastBroadcast
    );
    // EC-002 boundary: /30 broadcast is the last allowed prefix.
    let idx30 = index_for(&[("a", &["10.0.0.0/30"])]);
    assert_eq!(
        classify_dst(ip("10.0.0.3"), &idx30),
        DstKind::MulticastBroadcast
    );
}

// ── AC-005: /31 and /32 are excluded from directed broadcast ─────────────────

#[test]
fn test_BC_1_03_004_directed_broadcast_not_applied_to_31_32() {
    let idx31 = index_for(&[("a", &["10.0.0.0/31"])]);
    assert_eq!(classify_dst(ip("10.0.0.1"), &idx31), DstKind::Normal);
    let idx32 = index_for(&[("a", &["10.0.0.5/32"])]);
    assert_eq!(classify_dst(ip("10.0.0.5"), &idx32), DstKind::Normal);
}

// ── AC-007: directed broadcast is IPv4-only ──────────────────────────────────

#[test]
fn test_BC_1_03_004_directed_broadcast_ipv4_only() {
    // The all-ones host of an IPv6 zone is NOT a directed broadcast (no IPv6
    // broadcast concept); only Step-1 ff00::/8 would flag IPv6.
    let idx = index_for(&[("a", &["2001:db8::/120"])]);
    assert_eq!(
        classify_dst(ip("2001:db8::ff"), &idx),
        DstKind::Normal,
        "IPv6 all-ones host is not a directed broadcast"
    );
}

// ── Edge cases: network address, no-zone, unicast, middle-of-range ───────────

#[test]
fn test_BC_1_03_004_network_address_not_broadcast() {
    // EC-005/OQ-005: the network address (all-zeros host) is not exempted.
    let idx = index_for(&[("a", &["10.0.0.0/24"])]);
    assert_eq!(classify_dst(ip("10.0.0.0"), &idx), DstKind::Normal);
}

#[test]
fn test_BC_1_03_004_broadcast_without_matching_zone_is_normal() {
    // EC-005: .255 with no zone declaring its /24 → no directed broadcast.
    let idx = index_for(&[("a", &["192.168.0.0/24"])]);
    assert_eq!(classify_dst(ip("10.0.1.255"), &idx), DstKind::Normal);
}

#[test]
fn test_BC_1_03_004_unicast_and_middle_of_range_are_normal() {
    let idx = index_for(&[("a", &["10.0.0.0/24"])]);
    assert_eq!(classify_dst(ip("10.0.0.128"), &idx), DstKind::Normal); // EC-007
    assert_eq!(classify_dst(ip("192.168.1.5"), &idx), DstKind::Normal); // not in any zone
}

#[test]
fn test_BC_1_03_004_longest_match_31_blocks_override_from_shorter_30() {
    // If the longest-prefix match is a /31 (excluded), the override must NOT fire
    // even though a shorter /30 also contains the dst and has it as broadcast.
    let idx = index_for(&[("wide", &["10.0.0.0/30"]), ("ptp", &["10.0.0.2/31"])]);
    // 10.0.0.3 is broadcast of the /30, but the longest match is the /31.
    assert_eq!(classify_dst(ip("10.0.0.3"), &idx), DstKind::Normal);
}

// ── Property: every IPv4 address in 224.0.0.0/4 is detected (Step-1) ─────────

proptest! {
    #[test]
    fn test_BC_1_03_003_all_ipv4_multicast_detected(low in 0u32..=0x0FFF_FFFF) {
        // 224.0.0.0/4 == 0xE0000000 ..= 0xEFFFFFFF
        let addr = Ipv4Addr::from(0xE000_0000 | low);
        prop_assert_eq!(classify_dst(IpAddr::V4(addr), &Vec::new()), DstKind::MulticastBroadcast);
    }
}
