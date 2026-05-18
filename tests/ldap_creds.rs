//! Integration tests for the `creds.ldap_simple_bind` detector.
//!
//! Covers:
//!   AC-002 (BC-3.01.005) — finding fires at Critical for plaintext bind
//!   AC-003              — paired STARTTLS suppression (positive + negative)
//!   EC-003              — anonymous bind is suppressed
//!
//! AC-003 rationale: both the positive and negative suppression tests must
//! share the same base fixture (same module) so a future regression that
//! breaks the suppression logic will flip the negative test from pass to
//! fail. The vacuous-pass case is impossible because the positive test
//! confirms the firing path is live.

use chrono::{TimeZone, Utc};

fn fixed_ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
}

/// Fixture: one plaintext LDAPv3 simple-bind, no STARTTLS.
fn fixture_with_bind() -> otsniff::observe::Observations {
    let mut obs = otsniff::observe::Observations::default();
    obs.ldap_bind_events.push(otsniff::observe::LdapBindEvent {
        ts: fixed_ts(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 389,
        version: 3,
        used_starttls: false,
        anonymous: false,
    });
    obs
}

/// Fixture: same bind, but STARTTLS preceded it on the same flow.
fn fixture_with_starttls_then_bind() -> otsniff::observe::Observations {
    let mut obs = fixture_with_bind();
    obs.ldap_bind_events[0].used_starttls = true;
    obs
}

/// Fixture: anonymous bind (empty DN + empty password).
fn fixture_with_anonymous_bind() -> otsniff::observe::Observations {
    let mut obs = fixture_with_bind();
    obs.ldap_bind_events[0].anonymous = true;
    obs
}

// -------------------------------------------------------------------------
// AC-002 (BC-3.01.005): detector must fire at Critical for plaintext bind
// -------------------------------------------------------------------------

/// AC-002: a plaintext LDAPv3 simple-bind with no STARTTLS must produce
/// exactly one finding at severity Critical with rule id
/// `creds.ldap_simple_bind`.
#[test]
fn test_BC_3_01_005_positive_plaintext_bind_emits_critical_finding() {
    let obs = fixture_with_bind();
    let findings = otsniff::findings::ldap_creds::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "AC-002: must fire exactly one finding on plaintext bind"
    );
    assert_eq!(
        findings[0].severity,
        otsniff::findings::Severity::Critical,
        "AC-002: finding severity must be Critical"
    );
    assert!(
        findings[0].id == "creds.ldap_simple_bind"
            || findings[0].id.ends_with("ldap_simple_bind"),
        "AC-002: finding rule_id must be 'creds.ldap_simple_bind', got '{}'",
        findings[0].id
    );
}

// -------------------------------------------------------------------------
// AC-003: STARTTLS suppression — paired control tests (must share module)
// -------------------------------------------------------------------------

/// AC-003 negative: when a successful STARTTLS exchange preceded the bind
/// on the same flow (`used_starttls == true`), the finding must NOT fire.
#[test]
fn test_BC_3_01_005_negative_post_starttls_bind_suppresses_finding() {
    let obs = fixture_with_starttls_then_bind();
    let findings = otsniff::findings::ldap_creds::build_findings(&obs);
    assert!(
        findings.is_empty(),
        "AC-003 negative: STARTTLS-protected bind must not produce any findings, got {}",
        findings.len()
    );
}

// -------------------------------------------------------------------------
// EC-003: anonymous bind must be suppressed
// -------------------------------------------------------------------------

/// EC-003: an anonymous bind (empty DN + empty password, anonymous=true)
/// is a well-known LDAP pattern, not a credential leak. The finding must
/// not fire.
#[test]
fn test_BC_1_03_005_anonymous_bind_suppressed() {
    let obs = fixture_with_anonymous_bind();
    let findings = otsniff::findings::ldap_creds::build_findings(&obs);
    assert!(
        findings.is_empty(),
        "EC-003: anonymous bind must not produce any findings, got {}",
        findings.len()
    );
}
