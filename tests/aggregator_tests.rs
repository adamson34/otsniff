//! Integration tests for S-5.02 — aggregator (BC-1.05.001/004/005).
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use proptest::prelude::*;

use zonewarden_core::aggregator::{aggregate, checked_inc};
use zonewarden_core::errors::SysError;
use zonewarden_core::types::ValidatedPolicy;
use zonewarden_core::types::{
    AssetMatcher, ConduitId, Policy, PurdueLevel, Verdict, VerdictKind, Violation, Zone, ZoneId,
};
use zonewarden_core::validator::validate;

// ── helpers ──────────────────────────────────────────────────────────────────

fn vp() -> ValidatedPolicy {
    validate(Policy {
        zones: vec![Zone {
            id: ZoneId("a".to_string()),
            name: "a".to_string(),
            purdue_level: PurdueLevel::L2,
            sl_t: None,
            members: vec![AssetMatcher::Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix_len: 24,
            }],
        }],
        conduits: vec![],
    })
    .expect("valid policy")
}

fn kind(sel: u8) -> VerdictKind {
    match sel % 5 {
        0 => VerdictKind::IntraZone,
        1 => VerdictKind::Allowed(ConduitId(0)),
        2 => VerdictKind::NoMatchingConduit,
        3 => VerdictKind::WrongDirection,
        _ => VerdictKind::MulticastExempt,
    }
}

fn verdict(flow_index: u64, src: &str, dst: &str, kind: VerdictKind, idmz_bypass: bool) -> Verdict {
    Verdict {
        flow_index,
        src_zone: ZoneId(src.to_string()),
        dst_zone: ZoneId(dst.to_string()),
        kind,
        idmz_bypass,
    }
}

/// Pair a verdict with no violation rows (tally-only tests).
fn item(v: Verdict) -> (Verdict, Vec<Violation>) {
    (v, Vec::new())
}

// ── AC-006: checked increment overflow ───────────────────────────────────────

#[test]
fn test_BC_1_05_004_tally_overflow_returns_err() {
    assert_eq!(checked_inc(5), Ok(6));
    assert_eq!(checked_inc(u64::MAX), Err(SysError::TallyOverflow));
    assert_eq!(checked_inc(u64::MAX - 1), Ok(u64::MAX));
}

// ── AC-007 / AC-008: empty input → all-zero, identity holds ──────────────────

#[test]
fn test_BC_1_05_005_empty_input_all_zero() {
    let p = vp();
    let r = aggregate(Vec::new(), &p, 0, vec![]).expect("ok");
    assert_eq!(r.total_flows, 0);
    assert_eq!(r.intra_zone, 0);
    assert_eq!(r.allowed, 0);
    assert_eq!(r.no_matching_conduit, 0);
    assert_eq!(r.wrong_direction, 0);
    assert_eq!(r.multicast_exempt, 0);
    assert_eq!(r.idmz_bypasses, 0);
    assert_eq!(r.distinct_violating_flows, 0);
    assert_eq!(r.external_endpoints, 0);
    assert!(r.violations.is_empty());
    // identity: 0 == 0+0+0+0+0
    assert_eq!(
        r.total_flows,
        r.intra_zone + r.allowed + r.no_matching_conduit + r.wrong_direction + r.multicast_exempt
    );
    // digest still computed
    assert_eq!(r.policy_digest.len(), 64);
}

// ── AC-004: skipped is passed in, excluded from total_flows ──────────────────

#[test]
fn test_BC_1_05_001_skipped_not_in_total_flows() {
    let p = vp();
    let items = vec![
        item(verdict(0, "a", "b", VerdictKind::IntraZone, false)),
        item(verdict(
            1,
            "a",
            "b",
            VerdictKind::Allowed(ConduitId(0)),
            false,
        )),
    ];
    let r = aggregate(items, &p, 5, vec!["w".to_string()]).expect("ok");
    assert_eq!(r.total_flows, 2);
    assert_eq!(r.skipped, 5);
    assert_eq!(r.warnings, vec!["w".to_string()]);
}

// ── AC-005: external_endpoints is diagnostic, not in the identity ─────────────

#[test]
fn test_BC_1_05_001_external_endpoints_diagnostic_only() {
    let p = vp();
    // an Allowed flow with an EXTERNAL endpoint: counted in `allowed` AND
    // `external_endpoints`, but external_endpoints is not part of the identity.
    let items = vec![item(verdict(
        0,
        "a",
        ZoneId::EXTERNAL,
        VerdictKind::Allowed(ConduitId(0)),
        false,
    ))];
    let r = aggregate(items, &p, 0, vec![]).expect("ok");
    assert_eq!(r.allowed, 1);
    assert_eq!(r.external_endpoints, 1);
    assert_eq!(r.total_flows, 1);
    assert_eq!(
        r.total_flows,
        r.intra_zone + r.allowed + r.no_matching_conduit + r.wrong_direction + r.multicast_exempt
    );
}

// ── EC-004: Allowed AND idmz_bypass → both tallied; flow is violating ─────────

#[test]
fn test_BC_1_05_001_allowed_with_idmz_bypass() {
    let p = vp();
    let items = vec![item(verdict(
        0,
        "a",
        "b",
        VerdictKind::Allowed(ConduitId(0)),
        true,
    ))];
    let r = aggregate(items, &p, 0, vec![]).expect("ok");
    assert_eq!(r.allowed, 1);
    assert_eq!(r.idmz_bypasses, 1);
    assert_eq!(r.distinct_violating_flows, 1); // idmz_bypass makes the flow violating
    assert_eq!(r.total_flows, 1);
}

// ── distinct_violating_flows dedups by flow_index ────────────────────────────

#[test]
fn test_BC_1_05_001_distinct_violating_dedup_by_flow_index() {
    let p = vp();
    // two violating verdicts sharing a flow_index → counted once
    let items = vec![
        item(verdict(7, "a", "b", VerdictKind::NoMatchingConduit, false)),
        item(verdict(7, "a", "b", VerdictKind::NoMatchingConduit, false)),
    ];
    let r = aggregate(items, &p, 0, vec![]).expect("ok");
    assert_eq!(r.distinct_violating_flows, 1);
    assert_eq!(r.no_matching_conduit, 2);
    assert_eq!(r.total_flows, 2);
}

// ── violations list is collected ─────────────────────────────────────────────

#[test]
fn test_violations_collected_into_result() {
    let p = vp();
    let v = verdict(0, "a", "b", VerdictKind::NoMatchingConduit, false);
    let vio = Violation {
        flow_index: 0,
        src_zone: ZoneId("a".to_string()),
        dst_zone: ZoneId("b".to_string()),
        kind: zonewarden_core::types::ViolationKind::NoMatchingConduit,
        severity: zonewarden_core::types::Severity::Established,
        idmz_bypass: false,
        explanation: "x".to_string(),
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "10.0.1.1".parse().unwrap(),
        src_port: Some(1),
        dst_port: Some(502),
        proto: zonewarden_core::types::Proto::Tcp,
        service: None,
        service_source: zonewarden_core::types::ServiceSource::Unknown,
        conn_state: None,
    };
    let r = aggregate(vec![(v, vec![vio])], &p, 0, vec![]).expect("ok");
    assert_eq!(r.violations.len(), 1);
    assert_eq!(r.no_matching_conduit, 1);
}

// ── AC-001/002/003: DI-015 identity + bounds, over random verdict mixes ──────

proptest! {
    #[test]
    fn test_BC_1_05_001_di015_identity_holds(specs in prop::collection::vec((any::<u8>(), any::<bool>(), any::<bool>()), 0..200)) {
        let p = vp();
        let items: Vec<(Verdict, Vec<Violation>)> = specs.iter().enumerate().map(|(i, &(k, idmz, ext))| {
            let dst = if ext { ZoneId::EXTERNAL } else { "b" };
            item(verdict(i as u64, "a", dst, kind(k), idmz))
        }).collect();
        let n = items.len() as u64;
        let r = aggregate(items, &p, 0, vec![]).expect("no overflow for <200 flows");

        // DI-015 accounting identity
        prop_assert_eq!(
            r.total_flows,
            r.intra_zone + r.allowed + r.no_matching_conduit + r.wrong_direction + r.multicast_exempt
        );
        prop_assert_eq!(r.total_flows, n);
        // bounds (AC-002/003)
        prop_assert!(r.idmz_bypasses <= r.total_flows);
        prop_assert!(r.distinct_violating_flows <= r.total_flows);
        prop_assert!(r.external_endpoints <= r.total_flows);
    }
}
