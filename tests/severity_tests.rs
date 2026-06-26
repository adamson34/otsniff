//! Integration tests for S-4.01 — severity grading (BC-1.04.009, OQ-001).
//!
//! `severity` is the single source (DI-017) of the Zeek `conn_state` token →
//! `Severity` bucket mapping. These tests exercise the public API only.
//!
//! Test names intentionally use the upper-case `BC` contract id from the story
//! acceptance criteria.
#![allow(non_snake_case)]

use zonewarden_core::severity::{conn_state_from_token, grade};
use zonewarden_core::types::{ConnState, Severity};

/// End-to-end path a violation reporter takes: raw Zeek token → bucket → graded
/// severity.
fn grade_token(token: &str) -> Severity {
    grade(Some(&conn_state_from_token(token)))
}

// AC-001 (BC-1.04.009 postcondition 1): Established-bucket Zeek states grade to
// Established.
#[test]
fn test_BC_1_04_009_established_states_map_to_established() {
    for token in ["SF", "S2", "S3", "RSTO", "RSTR", "OTH"] {
        assert_eq!(grade_token(token), Severity::Established, "token {token}");
    }
    // Direct ConnState path.
    assert_eq!(grade(Some(&ConnState::Established)), Severity::Established);
}

// AC-002 (BC-1.04.009 postcondition 1): Attempted-bucket Zeek states grade to
// Attempted.
#[test]
fn test_BC_1_04_009_attempted_states_map_to_attempted() {
    for token in ["S0", "S1", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"] {
        assert_eq!(grade_token(token), Severity::Attempted, "token {token}");
    }
    // Direct ConnState path.
    assert_eq!(grade(Some(&ConnState::Attempted)), Severity::Attempted);
}

// AC-003 (BC-1.04.009 postcondition 2 / invariant 2): absent conn_state →
// Established (conservative default).
#[test]
fn test_BC_1_04_009_none_conn_state_defaults_to_established() {
    assert_eq!(grade(None), Severity::Established);
}

// AC-004 (BC-1.04.009 / OQ-001): the complete 13-state table is correct.
#[test]
fn test_BC_1_04_009_full_13_state_table_correct() {
    let table = [
        ("S0", Severity::Attempted),
        ("S1", Severity::Attempted),
        ("S2", Severity::Established),
        ("S3", Severity::Established),
        ("SF", Severity::Established),
        ("REJ", Severity::Attempted),
        ("RSTO", Severity::Established),
        ("RSTR", Severity::Established),
        ("RSTOS0", Severity::Attempted),
        ("RSTRH", Severity::Attempted),
        ("SH", Severity::Attempted),
        ("SHR", Severity::Attempted),
        ("OTH", Severity::Established),
    ];
    assert_eq!(table.len(), 13, "OQ-001 defines exactly 13 Zeek states");
    for (token, expected) in table {
        assert_eq!(grade_token(token), expected, "conn_state {token}");
    }
}

// EC-004 (BC-1.04.009 invariant 3): an unrecognized token becomes Other(_) and
// grades conservatively to Established.
#[test]
fn test_BC_1_04_009_unknown_state_is_other_and_grades_established() {
    assert_eq!(
        conn_state_from_token("CUSTOM"),
        ConnState::Other("CUSTOM".to_string())
    );
    assert_eq!(
        grade(Some(&ConnState::Other("CUSTOM".to_string()))),
        Severity::Established
    );
    assert_eq!(grade_token("CUSTOM"), Severity::Established);
}
