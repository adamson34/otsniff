//! Integration tests for S-4.03 — classifier core
//! (BC-1.04.001/002/003/004/005/006/009).
//!
//! Test names intentionally use the upper-case `BC` contract id.
#![allow(non_snake_case)]

use std::net::IpAddr;

use zonewarden_core::classifier::{classify, violations_for, ClassifyCtx};
use zonewarden_core::portset::PortSet;
use zonewarden_core::types::{
    AssetMatcher, Conduit, ConnState, Direction, DstKind, Flow, MatchKind, Proto, PurdueLevel,
    ResolvedEndpoint, ResolvedPair, ServiceSource, Severity, Timestamp, ValidatedPolicy, Verdict,
    VerdictKind, Violation, ViolationKind, Zone, ZoneId,
};
use zonewarden_core::validator::validate;

/// S-4.03 tests classify non-multicast flows; this wrapper passes Normal so they
/// stay readable. S-4.04 multicast tests call `classify` with the dst_kind.
fn classify_normal(ctx: &ClassifyCtx, flow: &Flow, pair: &ResolvedPair) -> Verdict {
    classify(ctx, flow, pair, DstKind::Normal)
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn zone(id: &str, level: PurdueLevel, cidr: &str) -> Zone {
    let (addr, plen) = cidr.split_once('/').unwrap();
    Zone {
        id: ZoneId(id.to_string()),
        name: id.to_string(),
        purdue_level: level,
        sl_t: None,
        members: vec![AssetMatcher::Cidr {
            addr: addr.parse().unwrap(),
            prefix_len: plen.parse().unwrap(),
        }],
    }
}

fn conduit(from: &str, to: &str, dir: Direction, proto: Proto, ports: PortSet) -> Conduit {
    Conduit {
        from_zone: ZoneId(from.to_string()),
        to_zone: ZoneId(to.to_string()),
        direction: dir,
        proto,
        ports,
    }
}

fn ports(pairs: &[(u16, u16)]) -> PortSet {
    PortSet::from_pairs(pairs).unwrap()
}

/// Validated policy: zones a (L2), b (L2), it (L4) + the given conduits.
fn vp(conduits: Vec<Conduit>) -> ValidatedPolicy {
    validate(zonewarden_core::types::Policy {
        zones: vec![
            zone("a", PurdueLevel::L2, "10.0.0.0/24"),
            zone("b", PurdueLevel::L2, "10.0.1.0/24"),
            zone("it", PurdueLevel::L4, "10.0.2.0/24"),
        ],
        conduits,
    })
    .expect("valid policy")
}

fn ep(zone_id: &str) -> ResolvedEndpoint {
    ResolvedEndpoint {
        ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
        zone_id: ZoneId(zone_id.to_string()),
        match_kind: MatchKind::Explicit { prefix_len: 24 },
    }
}

fn pair(src: &str, dst: &str) -> ResolvedPair {
    ResolvedPair {
        src: ep(src),
        dst: ep(dst),
    }
}

fn flow(proto: Proto, dst_port: Option<u16>, conn_state: Option<ConnState>) -> Flow {
    Flow {
        flow_index: 7,
        ts: Timestamp(0),
        src_ip: "10.0.0.5".parse().unwrap(),
        src_port: Some(40000),
        dst_ip: "10.0.1.5".parse().unwrap(),
        dst_port,
        proto,
        service: None,
        service_source: ServiceSource::Unknown,
        conn_state,
    }
}

// ── AC-001: same zone → IntraZone, no conduit eval, no IDMZ ───────────────────

#[test]
fn test_BC_1_04_001_same_zone_intra_zone() {
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("a", "a"));
    assert_eq!(v.kind, VerdictKind::IntraZone);
    assert!(!v.idmz_bypass);
}

#[test]
fn test_BC_1_04_001_intra_zone_skips_idmz_check() {
    // Even if the (impossible-in-practice) same-zone case were cross-level, the
    // IntraZone branch must short-circuit with idmz_bypass = false (AC-009).
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("it", "it"));
    assert_eq!(v.kind, VerdictKind::IntraZone);
    assert!(!v.idmz_bypass);
}

// ── AC-002: deny-by-default → NoMatchingConduit ──────────────────────────────

#[test]
fn test_BC_1_04_002_no_matching_conduit_verdict() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    // right zone-pair + proto, wrong port → no match
    let v = classify_normal(&ctx, &flow(Proto::Tcp, Some(9999), None), &pair("a", "b"));
    assert_eq!(v.kind, VerdictKind::NoMatchingConduit);
}

#[test]
fn test_BC_1_04_002_proto_mismatch_no_match() {
    // EC-008: UDP/502 against a TCP/502 conduit → NoMatchingConduit.
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify_normal(&ctx, &flow(Proto::Udp, Some(502), None), &pair("a", "b"));
    assert_eq!(v.kind, VerdictKind::NoMatchingConduit);
}

// ── AC-003: any-match union; first matching conduit wins ──────────────────────

#[test]
fn test_BC_1_04_003_any_match_first_conduit_permits() {
    let p = vp(vec![
        conduit(
            "a",
            "b",
            Direction::Forward,
            Proto::Tcp,
            ports(&[(502, 502)]),
        ),
        conduit(
            "a",
            "b",
            Direction::Forward,
            Proto::Tcp,
            ports(&[(44818, 44818)]),
        ),
    ]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("a", "b"));
    assert_eq!(
        v.kind,
        VerdictKind::Allowed(zonewarden_core::types::ConduitId(0))
    );
    // EC-003: second conduit matches when first doesn't
    let v2 = classify_normal(&ctx, &flow(Proto::Tcp, Some(44818), None), &pair("a", "b"));
    assert_eq!(
        v2.kind,
        VerdictKind::Allowed(zonewarden_core::types::ConduitId(1))
    );
}

#[test]
fn test_BC_1_04_003_port_range_inclusive() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(500, 510)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    for port in [500u16, 505, 510] {
        let v = classify_normal(&ctx, &flow(Proto::Tcp, Some(port), None), &pair("a", "b"));
        assert!(matches!(v.kind, VerdictKind::Allowed(_)), "port {port}");
    }
    let out = classify_normal(&ctx, &flow(Proto::Tcp, Some(511), None), &pair("a", "b"));
    assert_eq!(out.kind, VerdictKind::NoMatchingConduit);
}

// ── AC-004: Forward conduit rejects reverse → WrongDirection ──────────────────

#[test]
fn test_BC_1_04_004_forward_conduit_rejects_reverse() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    // forward direction allowed
    assert!(matches!(
        classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("a", "b")).kind,
        VerdictKind::Allowed(_)
    ));
    // reverse direction → WrongDirection
    let rev = classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("b", "a"));
    assert_eq!(rev.kind, VerdictKind::WrongDirection);
}

// ── AC-008: WrongDirection beats NoMatchingConduit ───────────────────────────

#[test]
fn test_BC_1_04_004_wrong_direction_beats_no_match() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    // reverse + matching proto/port → WrongDirection
    assert_eq!(
        classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("b", "a")).kind,
        VerdictKind::WrongDirection
    );
    // reverse + non-matching port → NoMatchingConduit (no conduit matches at all)
    assert_eq!(
        classify_normal(&ctx, &flow(Proto::Tcp, Some(9999), None), &pair("b", "a")).kind,
        VerdictKind::NoMatchingConduit
    );
}

// ── AC-005: Bidirectional permits both directions ────────────────────────────

#[test]
fn test_BC_1_04_005_bidirectional_permits_both_directions() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Bidirectional,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    assert!(matches!(
        classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("a", "b")).kind,
        VerdictKind::Allowed(_)
    ));
    assert!(matches!(
        classify_normal(&ctx, &flow(Proto::Tcp, Some(502), None), &pair("b", "a")).kind,
        VerdictKind::Allowed(_)
    ));
}

// ── AC-006: portless (ICMP) matches only PortSet::Any ────────────────────────

#[test]
fn test_BC_1_04_006_icmp_matches_any_portset_only() {
    // EC-007: ICMP + conduit ports Any (proto icmp) → Allowed
    let p_any = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Icmp,
        PortSet::Any,
    )]);
    let ctx_any = ClassifyCtx { policy: &p_any };
    assert!(matches!(
        classify_normal(&ctx_any, &flow(Proto::Icmp, None, None), &pair("a", "b")).kind,
        VerdictKind::Allowed(_)
    ));
    // EC-006: ICMP + conduit with explicit ports → NoMatchingConduit
    let p_ports = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Icmp,
        ports(&[(502, 502)]),
    )]);
    let ctx_ports = ClassifyCtx { policy: &p_ports };
    assert_eq!(
        classify_normal(&ctx_ports, &flow(Proto::Icmp, None, None), &pair("a", "b")).kind,
        VerdictKind::NoMatchingConduit
    );
    // proto must match: a tcp/Any conduit does NOT cover an ICMP flow
    let p_tcp_any = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        PortSet::Any,
    )]);
    let ctx_tcp = ClassifyCtx { policy: &p_tcp_any };
    assert_eq!(
        classify_normal(&ctx_tcp, &flow(Proto::Icmp, None, None), &pair("a", "b")).kind,
        VerdictKind::NoMatchingConduit
    );
}

// ── AC-007 / BC-1.04.009: violation severity from conn_state ─────────────────

#[test]
fn test_BC_1_04_009_violation_severity_from_conn_state() {
    let p = vp(vec![]); // no conduits → NoMatchingConduit for a->b
    let ctx = ClassifyCtx { policy: &p };
    let f = flow(Proto::Tcp, Some(502), Some(ConnState::Established));
    let pr = pair("a", "b");
    let v = classify_normal(&ctx, &f, &pr);
    assert_eq!(v.kind, VerdictKind::NoMatchingConduit);

    let vios = violations_for(&f, &pr, &v);
    assert_eq!(vios.len(), 1);
    assert_eq!(vios[0].kind, ViolationKind::NoMatchingConduit);
    assert_eq!(vios[0].severity, Severity::Established);
    assert_eq!(vios[0].flow_index, 7);
    assert_eq!(vios[0].dst_port, Some(502));
}

#[test]
fn test_BC_1_04_009_none_conn_state_defaults_established() {
    // EC-009: conn_state None on a violation → Established (conservative).
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let f = flow(Proto::Tcp, Some(502), None);
    let pr = pair("a", "b");
    let v = classify_normal(&ctx, &f, &pr);
    let vios = violations_for(&f, &pr, &v);
    assert_eq!(vios[0].severity, Severity::Established);
}

#[test]
fn test_no_violations_for_allowed_or_intrazone() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    // Allowed → no violation rows
    let f = flow(Proto::Tcp, Some(502), None);
    let pr = pair("a", "b");
    let v = classify_normal(&ctx, &f, &pr);
    assert!(matches!(v.kind, VerdictKind::Allowed(_)));
    assert!(violations_for(&f, &pr, &v).is_empty());
    // IntraZone → no violation rows
    let pr2 = pair("a", "a");
    let v2 = classify_normal(&ctx, &f, &pr2);
    assert!(violations_for(&f, &pr2, &v2).is_empty());
}

// ── BC-1.04.007 additive: Allowed AND idmz_bypass; two violation rows ────────

#[test]
fn test_BC_1_04_007_idmz_bypass_additive_to_allowed() {
    // a (L2 OT) -> it (L4 IT), permitted by a conduit, but still an IDMZ bypass.
    let p = vp(vec![conduit(
        "a",
        "it",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    let f = flow(Proto::Tcp, Some(502), Some(ConnState::Established));
    let pr = pair("a", "it");
    let v = classify_normal(&ctx, &f, &pr);
    assert!(matches!(v.kind, VerdictKind::Allowed(_)));
    assert!(
        v.idmz_bypass,
        "OT->IT flow is an IDMZ bypass even when Allowed"
    );

    let vios = violations_for(&f, &pr, &v);
    // Allowed → no conduit violation, but the additive IdmzBypass row is present.
    assert_eq!(vios.len(), 1);
    assert_eq!(vios[0].kind, ViolationKind::IdmzBypass);
    assert!(vios[0].idmz_bypass);
}

#[test]
fn test_BC_1_04_007_no_match_plus_idmz_yields_two_violations() {
    // a (L2) -> it (L4), no conduit → NoMatchingConduit AND IdmzBypass.
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let f = flow(Proto::Tcp, Some(502), Some(ConnState::Attempted));
    let pr = pair("a", "it");
    let v = classify_normal(&ctx, &f, &pr);
    assert_eq!(v.kind, VerdictKind::NoMatchingConduit);
    assert!(v.idmz_bypass);

    let vios = violations_for(&f, &pr, &v);
    let kinds: Vec<&ViolationKind> = vios.iter().map(|x| &x.kind).collect();
    assert_eq!(vios.len(), 2);
    assert!(kinds.contains(&&ViolationKind::NoMatchingConduit));
    assert!(kinds.contains(&&ViolationKind::IdmzBypass));
    // both rows carry the flow's graded severity (Attempted)
    assert!(vios
        .iter()
        .all(|x: &Violation| x.severity == Severity::Attempted));
}

// ── S-4.04: MulticastExempt short-circuit + verdict totality ─────────────────

// AC-001: multicast dst → MulticastExempt, before conduit eval.
#[test]
fn test_BC_1_04_011_multicast_dst_short_circuits() {
    // a conduit a->b exists, but a multicast dst short-circuits past it.
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify(
        &ctx,
        &flow(Proto::Udp, Some(47808), None),
        &pair("a", "b"),
        DstKind::MulticastBroadcast,
    );
    assert_eq!(v.kind, VerdictKind::MulticastExempt);
}

// AC-002: MulticastExempt outranks IntraZone (same zone + multicast dst).
#[test]
fn test_BC_1_04_011_multicast_before_intrazone() {
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify(
        &ctx,
        &flow(Proto::Udp, Some(47808), None),
        &pair("a", "a"), // same zone — would be IntraZone if not multicast
        DstKind::MulticastBroadcast,
    );
    assert_eq!(v.kind, VerdictKind::MulticastExempt);
}

// AC-004: MulticastExempt forces idmz_bypass = false (even on an OT->IT pair).
#[test]
fn test_BC_1_04_011_multicast_exempt_no_idmz_bypass() {
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let v = classify(
        &ctx,
        &flow(Proto::Udp, Some(47808), None),
        &pair("a", "it"), // OT -> IT: would be a bypass on Normal
        DstKind::MulticastBroadcast,
    );
    assert_eq!(v.kind, VerdictKind::MulticastExempt);
    assert!(!v.idmz_bypass);
}

// AC-006: MulticastExempt yields no violation rows.
#[test]
fn test_BC_1_04_011_multicast_exempt_not_in_violations() {
    let p = vp(vec![]);
    let ctx = ClassifyCtx { policy: &p };
    let f = flow(Proto::Udp, Some(47808), Some(ConnState::Established));
    let pr = pair("a", "it");
    let v = classify(&ctx, &f, &pr, DstKind::MulticastBroadcast);
    assert!(violations_for(&f, &pr, &v).is_empty());
}

// AC-003 / EC-004: all five VerdictKinds are reachable — totality across kinds.
#[test]
fn test_BC_1_04_010_verdict_totality_all_kinds() {
    let p = vp(vec![conduit(
        "a",
        "b",
        Direction::Forward,
        Proto::Tcp,
        ports(&[(502, 502)]),
    )]);
    let ctx = ClassifyCtx { policy: &p };
    let f = flow(Proto::Tcp, Some(502), None);

    let mc = classify(&ctx, &f, &pair("a", "b"), DstKind::MulticastBroadcast);
    let intra = classify(&ctx, &f, &pair("a", "a"), DstKind::Normal);
    let allowed = classify(&ctx, &f, &pair("a", "b"), DstKind::Normal);
    let wrong = classify(&ctx, &f, &pair("b", "a"), DstKind::Normal);
    let nomatch = classify(
        &ctx,
        &flow(Proto::Tcp, Some(9999), None),
        &pair("a", "b"),
        DstKind::Normal,
    );

    assert_eq!(mc.kind, VerdictKind::MulticastExempt);
    assert_eq!(intra.kind, VerdictKind::IntraZone);
    assert!(matches!(allowed.kind, VerdictKind::Allowed(_)));
    assert_eq!(wrong.kind, VerdictKind::WrongDirection);
    assert_eq!(nomatch.kind, VerdictKind::NoMatchingConduit);
}
