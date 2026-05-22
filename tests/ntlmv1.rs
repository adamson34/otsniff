//! Integration tests for the `compat.ntlmv1` detector.
//!
//! Covers:
//!   AC-002 (BC-3.04.004) — finding fires at High for NTLMv1
//!   EC-001               — NTLMv2 must not fire this finding
//!   AC-002 rollup        — events rolled up by (src, dst) pair

use chrono::{TimeZone, Utc};

fn fixed_ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
}

/// Fixture: one NTLMv1 event (src=10.0.0.1 → dst=10.0.0.2, port 445).
fn fixture_ntlmv1() -> otsniff::observe::Observations {
    let mut obs = otsniff::observe::Observations::default();
    obs.ntlm_events.push(otsniff::observe::NtlmEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 445,
        version: otsniff::observe::NtlmVersion::V1,
    });
    obs
}

/// Fixture: one NTLMv2 event — same hosts/port, only version differs.
fn fixture_ntlmv2() -> otsniff::observe::Observations {
    let mut obs = otsniff::observe::Observations::default();
    obs.ntlm_events.push(otsniff::observe::NtlmEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 445,
        version: otsniff::observe::NtlmVersion::V2,
    });
    obs
}

// -------------------------------------------------------------------------
// AC-002 (BC-3.04.004): detector must fire at High for NTLMv1
// -------------------------------------------------------------------------

/// AC-002: a single NTLMv1 event must produce exactly one finding at severity
/// High with rule id `compat.ntlmv1`.
#[test]
fn test_bc_3_04_004_positive_ntlmv1_emits_high_finding() {
    let obs = fixture_ntlmv1();
    let findings = otsniff::findings::ntlmv1::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "AC-002: must fire exactly one finding when a NTLMv1 event is observed"
    );
    assert_eq!(
        findings[0].severity,
        otsniff::findings::Severity::High,
        "AC-002: finding severity must be High"
    );
    assert!(
        findings[0].id == "compat.ntlmv1" || findings[0].id.ends_with("ntlmv1"),
        "AC-002: finding rule_id must be 'compat.ntlmv1', got '{}'",
        findings[0].id
    );
}

// -------------------------------------------------------------------------
// EC-001: NTLMv2 must not trigger this finding
// -------------------------------------------------------------------------

/// EC-001: a NTLMv2 event must NOT produce any `compat.ntlmv1` findings.
/// NTLMv2 is a distinct case handled by a different (future) rule.
#[test]
fn test_bc_3_04_004_negative_ntlmv2_does_not_fire() {
    let obs = fixture_ntlmv2();
    let findings = otsniff::findings::ntlmv1::build_findings(&obs);
    assert!(
        findings.is_empty(),
        "EC-001: NTLMv2 event must not trigger compat.ntlmv1, got {} finding(s)",
        findings.len()
    );
}

// -------------------------------------------------------------------------
// AC-002 rollup: events rolled up by (src, dst) pair
// -------------------------------------------------------------------------

/// AC-002 rollup: two NTLMv1 events from the same (src, dst) but different
/// dst_port must collapse to a single finding. A third event from a different
/// src must yield a second finding.
#[test]
fn test_bc_3_04_004_rolls_up_by_src_dst() {
    let mut obs = otsniff::observe::Observations::default();
    // Same (src, dst), different ports — should collapse to one finding.
    obs.ntlm_events.push(otsniff::observe::NtlmEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 445,
        version: otsniff::observe::NtlmVersion::V1,
    });
    obs.ntlm_events.push(otsniff::observe::NtlmEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 139,
        version: otsniff::observe::NtlmVersion::V1,
    });

    let findings = otsniff::findings::ntlmv1::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "AC-002 rollup: two V1 events from the same (src, dst) must collapse to one finding"
    );

    // Add a third event from a different src → should produce a second finding.
    obs.ntlm_events.push(otsniff::observe::NtlmEvent {
        ts: fixed_ts(),
        src: "10.0.0.3".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 445,
        version: otsniff::observe::NtlmVersion::V1,
    });

    let findings = otsniff::findings::ntlmv1::build_findings(&obs);
    assert_eq!(
        findings.len(),
        2,
        "AC-002 rollup: a V1 event from a distinct src must yield a second finding"
    );
}
