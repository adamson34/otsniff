//! Integration tests for the `creds.rdp_no_nla` detector (S-2.08).
//!
//! Covers:
//!   AC-002 (BC-3.04.006) — finding fires at Critical for PROTOCOL_RDP
//!   EC-001               — PROTOCOL_SSL must not fire
//!   EC-002               — PROTOCOL_HYBRID (0x02) must not fire
//!                          (catches AC-002 bit-test ambiguity: 0x02 & 0x01 == 0
//!                           would spuriously fire; correct intent is ==0x00 only)
//!   EC-003               — PROTOCOL_HYBRID_EX (0x08) must not fire
//!   AC-002 rollup        — events rolled up by (src, dst) pair

use chrono::{TimeZone, Utc};

fn fixed_ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
}

// -------------------------------------------------------------------------
// AC-002 (BC-3.04.006): detector must fire at Critical for PROTOCOL_RDP
// -------------------------------------------------------------------------

/// AC-002: a single RdpEvent with selectedProtocol=0 (PROTOCOL_RDP, no NLA)
/// must produce exactly one finding at severity Critical with rule id
/// `creds.rdp_no_nla`.
#[test]
fn test_bc_3_04_006_positive_protocol_rdp_fires_critical() {
    let mut obs = otsniff::observe::Observations::default();
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3389,
        selected_protocol: 0x00000000,
    });

    let findings = otsniff::findings::rdp_legacy::build_findings(&obs);

    assert_eq!(
        findings.len(),
        1,
        "AC-002: must fire exactly one finding when PROTOCOL_RDP (selected_protocol=0) is observed"
    );
    assert_eq!(
        findings[0].severity,
        otsniff::findings::Severity::Critical,
        "AC-002: finding severity must be Critical"
    );
    assert!(
        findings[0].id == "creds.rdp_no_nla" || findings[0].id.ends_with("rdp_no_nla"),
        "AC-002: finding rule_id must be 'creds.rdp_no_nla', got '{}'",
        findings[0].id
    );
}

// -------------------------------------------------------------------------
// Negative cases: PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX must
// NOT trigger creds.rdp_no_nla
//
// IMPORTANT NOTE FOR IMPLEMENTER: AC-002 in the story states
// `selected_protocol & 0x01 == 0` as the fire condition, but this bit-test
// is incorrect — it would spuriously fire on PROTOCOL_HYBRID (0x02) and
// PROTOCOL_HYBRID_EX (0x08) because 0x02 & 0x01 == 0 and 0x08 & 0x01 == 0.
// The tests below pin the CORRECT intent: only PROTOCOL_RDP (0x00000000)
// fires. The implementer must use `selected_protocol == 0x00000000` (exact
// equality), not the bit-test from AC-002.
// -------------------------------------------------------------------------

/// EC-001 (story) / negative: PROTOCOL_SSL (selectedProtocol=0x00000001) must
/// NOT produce any creds.rdp_no_nla finding.
#[test]
fn test_bc_3_04_006_negative_protocol_ssl_does_not_fire() {
    let mut obs = otsniff::observe::Observations::default();
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3389,
        selected_protocol: 0x00000001,
    });

    let findings = otsniff::findings::rdp_legacy::build_findings(&obs);

    assert!(
        findings.is_empty(),
        "PROTOCOL_SSL (selected_protocol=1) must not trigger creds.rdp_no_nla, \
         got {} finding(s)",
        findings.len()
    );
}

/// AC-002 bit-test guard: PROTOCOL_HYBRID (selectedProtocol=0x00000002, CredSSP/NLA)
/// must NOT produce any creds.rdp_no_nla finding.
///
/// The story's `selected_protocol & 0x01 == 0` would spuriously fire here
/// because 0x02 & 0x01 == 0. The correct implementation fires only on
/// selected_protocol == 0x00000000.
#[test]
fn test_bc_3_04_006_negative_protocol_hybrid_does_not_fire() {
    let mut obs = otsniff::observe::Observations::default();
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3389,
        selected_protocol: 0x00000002,
    });

    let findings = otsniff::findings::rdp_legacy::build_findings(&obs);

    assert!(
        findings.is_empty(),
        "PROTOCOL_HYBRID (selected_protocol=2, CredSSP/NLA) must not trigger \
         creds.rdp_no_nla — AC-002 bit-test 'x & 0x01 == 0' is incorrect here; \
         only selected_protocol == 0 should fire. Got {} finding(s)",
        findings.len()
    );
}

/// AC-002 bit-test guard: PROTOCOL_HYBRID_EX (selectedProtocol=0x00000008)
/// must NOT produce any creds.rdp_no_nla finding.
///
/// Same issue as PROTOCOL_HYBRID: 0x08 & 0x01 == 0 would spuriously fire
/// under the story's stated bit-test. Correct intent: only 0x00 fires.
#[test]
fn test_bc_3_04_006_negative_protocol_hybrid_ex_does_not_fire() {
    let mut obs = otsniff::observe::Observations::default();
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3389,
        selected_protocol: 0x00000008,
    });

    let findings = otsniff::findings::rdp_legacy::build_findings(&obs);

    assert!(
        findings.is_empty(),
        "PROTOCOL_HYBRID_EX (selected_protocol=8) must not trigger creds.rdp_no_nla, \
         got {} finding(s)",
        findings.len()
    );
}

// -------------------------------------------------------------------------
// AC-002 rollup: events rolled up by (src, dst) pair
// -------------------------------------------------------------------------

/// AC-002 rollup: two RdpEvents from the same (src, dst) but different
/// dst_ports must collapse to a single finding. A third event from a
/// different src must yield a second finding.
#[test]
fn test_bc_3_04_006_rolls_up_by_src_dst() {
    let mut obs = otsniff::observe::Observations::default();

    // Same (src, dst), different dst_ports — should collapse to one finding.
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3389,
        selected_protocol: 0x00000000,
    });
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3390,
        selected_protocol: 0x00000000,
    });

    let findings = otsniff::findings::rdp_legacy::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "AC-002 rollup: two PROTOCOL_RDP events from the same (src, dst) must \
         collapse to one finding"
    );

    // Add a third event from a different src → must yield a second finding.
    obs.rdp_events.push(otsniff::observe::RdpEvent {
        ts: fixed_ts(),
        src: "10.0.0.3".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 3389,
        selected_protocol: 0x00000000,
    });

    let findings = otsniff::findings::rdp_legacy::build_findings(&obs);
    assert_eq!(
        findings.len(),
        2,
        "AC-002 rollup: a PROTOCOL_RDP event from a distinct src must yield a second finding"
    );
}
