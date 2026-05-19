//! Smoke test for the prompt-eval rubric parser.
//! AC-002: invokes the parser in --dry-run mode, asserts rubric files parse without error.
//!
//! BC-6.02.001: rubric parser accepts well-formed numbered must/should/must-not assertions.
//! BC-AUDIT-013: rubric files on disk all parse without error.
//!
//! Test names use the BC-based `test_BC_S_SS_NNN_xxx` naming convention (VSDD TDD standard).
//! The uppercase letters are deliberate; allow non_snake_case only for this file.
#![allow(non_snake_case)]

#[derive(Debug)]
struct RubricAssertion {
    severity: AssertionSeverity,
    pattern: String,
}

#[derive(Debug, PartialEq)]
enum AssertionSeverity {
    Must,
    Should,
    MustNot,
}

fn parse_rubric(_text: &str) -> Result<Vec<RubricAssertion>, String> {
    todo!("S-3.02: rubric parser lands in step 4")
}

// ---------------------------------------------------------------------------
// BC-6.02.001 — individual severity keywords
// ---------------------------------------------------------------------------

/// test_BC_6_02_001_must_assertion
/// A single numbered MUST line parses to severity Must with the remainder as pattern.
#[test]
fn test_BC_6_02_001_must_assertion() {
    let input = "1. MUST contain a Priority-1 reference to host_001";
    let result = parse_rubric(input).expect("should parse valid MUST assertion");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].severity, AssertionSeverity::Must);
    // Pattern must contain the meaningful part; implementer decides exact split.
    assert!(
        !result[0].pattern.is_empty(),
        "pattern should not be empty"
    );
    assert!(
        result[0].pattern.contains("host_001"),
        "pattern should include the assertion text after the MUST keyword"
    );
}

/// test_BC_6_02_001_should_assertion
/// A single numbered SHOULD line parses to severity Should.
#[test]
fn test_BC_6_02_001_should_assertion() {
    let input = "1. SHOULD qualify topology claims when capture_source is host-side";
    let result = parse_rubric(input).expect("should parse valid SHOULD assertion");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].severity, AssertionSeverity::Should);
    assert!(
        result[0].pattern.contains("topology") || result[0].pattern.contains("capture_source"),
        "pattern should preserve assertion text"
    );
}

/// test_BC_6_02_001_must_not_assertion
/// A single numbered MUST NOT line parses to severity MustNot.
#[test]
fn test_BC_6_02_001_must_not_assertion() {
    let input = "1. MUST NOT mention any IP/MAC/hostname in real form";
    let result = parse_rubric(input).expect("should parse valid MUST NOT assertion");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].severity, AssertionSeverity::MustNot);
    assert!(
        result[0].pattern.contains("IP") || result[0].pattern.contains("hostname"),
        "pattern should preserve assertion text"
    );
}

/// test_BC_6_02_001_multiple_assertions
/// Three numbered lines (one of each severity) produce a Vec of 3 in order.
#[test]
fn test_BC_6_02_001_multiple_assertions() {
    let input = "\
1. MUST contain a Priority-1 reference to host_001
2. SHOULD qualify topology claims when capture_source is host-side
3. MUST NOT mention any IP/MAC/hostname in real form";
    let result = parse_rubric(input).expect("should parse three assertions");
    assert_eq!(result.len(), 3, "expected exactly 3 assertions");
    assert_eq!(result[0].severity, AssertionSeverity::Must);
    assert_eq!(result[1].severity, AssertionSeverity::Should);
    assert_eq!(result[2].severity, AssertionSeverity::MustNot);
}

// ---------------------------------------------------------------------------
// BC-6.02.001 — rejection of malformed input
// ---------------------------------------------------------------------------

/// test_BC_6_02_001_rejects_malformed_input
/// Plain text with no recognisable rubric structure returns Err.
#[test]
fn test_BC_6_02_001_rejects_malformed_input() {
    let input = "random text not in rubric format";
    let result = parse_rubric(input);
    assert!(
        result.is_err(),
        "malformed input with no assertion lines should return Err, got Ok"
    );
}

// ---------------------------------------------------------------------------
// BC-6.02.001 — blank lines and markdown comments are skipped
// ---------------------------------------------------------------------------

/// test_BC_6_02_001_skips_blank_lines_and_comments
/// Blank lines and `#` comment lines are ignored; only assertion lines count.
#[test]
fn test_BC_6_02_001_skips_blank_lines_and_comments() {
    let input = "\
# This is a rubric for the SPAN eval
# Author: test-writer

1. MUST contain a Priority-1 finding

2. SHOULD mention at least one OT asset

# Trailing comment
";
    let result = parse_rubric(input).expect("should parse despite blank lines and comments");
    assert_eq!(
        result.len(),
        2,
        "expected 2 assertions; blank lines and # comments must be skipped"
    );
    assert_eq!(result[0].severity, AssertionSeverity::Must);
    assert_eq!(result[1].severity, AssertionSeverity::Should);
}

// ---------------------------------------------------------------------------
// BC-AUDIT-013 — all on-disk rubric files parse without error
// ---------------------------------------------------------------------------

/// test_BC_AUDIT_013_parse_existing_rubric_files
/// Discovers every tests/prompt-evals/*/rubric.md and asserts each parses
/// without error and yields at least 1 assertion.
///
/// This test will FAIL until Step 4 fills in the actual rubric files.
#[test]
fn test_BC_AUDIT_013_parse_existing_rubric_files() {
    use std::fs;
    use std::path::Path;

    let evals_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/prompt-evals");

    let entries: Vec<_> = fs::read_dir(&evals_dir)
        .expect("tests/prompt-evals must exist")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    assert!(
        !entries.is_empty(),
        "no subdirectories found in tests/prompt-evals/"
    );

    let mut rubric_count = 0;
    for entry in entries {
        let rubric_path = entry.path().join("rubric.md");
        if !rubric_path.exists() {
            // File not yet created — fail with a descriptive message.
            panic!(
                "rubric.md missing in {:?}; implementer must create it in step 4",
                entry.path()
            );
        }
        let text = fs::read_to_string(&rubric_path)
            .unwrap_or_else(|e| panic!("could not read {:?}: {}", rubric_path, e));
        let assertions = parse_rubric(&text).unwrap_or_else(|e| {
            panic!("parse_rubric failed for {:?}: {}", rubric_path, e)
        });
        assert!(
            !assertions.is_empty(),
            "{:?} parsed to zero assertions",
            rubric_path
        );
        rubric_count += 1;
    }

    assert!(
        rubric_count >= 4,
        "expected at least 4 rubric files (one per capture-source variant), found {}",
        rubric_count
    );
}
