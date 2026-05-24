//! Acceptance tests for S-4.04: Kani composed proof of the privacy invariant.
//!
//! These are static / structural tests (facade TDD mode). They verify that
//! `src/kani_proofs.rs` and `docs/proofs/privacy-invariant.md` have the right
//! shape and contain no TODO placeholders.  The actual proof execution is
//! verified by `.github/workflows/kani.yml`.
//!
//! Traces to: BC-5.02.003

use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn worktree_root() -> &'static Path {
    // The integration-test binary is invoked from the crate root; all paths
    // are relative to that crate root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(rel: &str) -> String {
    let path = worktree_root().join(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {rel}: {e}"))
}

fn file_exists(rel: &str) -> bool {
    worktree_root().join(rel).exists()
}

// ---------------------------------------------------------------------------
// AC-001 — composed harness exists and has the right shape
// ---------------------------------------------------------------------------

/// AC-001: src/kani_proofs.rs must exist.
#[test]
fn test_ac_001_composed_harness_file_exists() {
    assert!(
        file_exists("src/kani_proofs.rs"),
        "AC-001: composed harness file src/kani_proofs.rs does not exist"
    );
}

/// AC-001: src/lib.rs must register the kani_proofs module under #[cfg(kani)].
#[test]
fn test_ac_001_module_registered_in_lib_rs() {
    let content = read_file("src/lib.rs");

    // Accept either `#[cfg(kani)] mod kani_proofs;` or the multi-line form
    // where the attribute and the mod declaration are on adjacent lines.
    let normalised = content.replace('\n', " ");
    let registered = normalised.contains("#[cfg(kani)] mod kani_proofs")
        || normalised.contains("#[cfg(kani)]  mod kani_proofs")
        || {
            // Two-line form: attribute on one line, mod on the next
            content.contains("#[cfg(kani)]")
                && content.contains("mod kani_proofs")
        };

    assert!(
        registered,
        "AC-001: src/lib.rs must contain '#[cfg(kani)] mod kani_proofs;' \
         (or equivalent two-line form) — not found"
    );
}

/// AC-001: src/kani_proofs.rs must contain a `#[kani::proof]` attribute
/// followed (anywhere in the file) by `fn composed_privacy_invariant`.
#[test]
fn test_ac_001_composed_proof_function_present() {
    let content = read_file("src/kani_proofs.rs");

    assert!(
        content.contains("#[kani::proof]"),
        "AC-001: src/kani_proofs.rs must contain a '#[kani::proof]' attribute"
    );
    assert!(
        content.contains("fn composed_privacy_invariant"),
        "AC-001: src/kani_proofs.rs must contain 'fn composed_privacy_invariant'"
    );
}

/// AC-001: the composed proof must reference BOTH `scrub` and `leak_detector`
/// modules — it is supposed to compose them, not just call one.
#[test]
fn test_ac_001_uses_both_scrub_and_leak_detector() {
    let content = read_file("src/kani_proofs.rs");

    let mentions_scrub = content.contains("crate::scrub")
        || content.contains("scrub::")
        || content.contains("use super::scrub")
        || content.contains("use crate::scrub");

    let mentions_leak = content.contains("crate::ai::leak_detector")
        || content.contains("leak_detector::")
        || content.contains("use super::leak_detector")
        || content.contains("use crate::ai::leak_detector");

    assert!(
        mentions_scrub && mentions_leak,
        "AC-001: composed harness must compose scrub() and ensure_clean() \
         together — neither or only one symbol found in src/kani_proofs.rs \
         (scrub present: {mentions_scrub}, leak_detector present: {mentions_leak})"
    );
}

/// AC-001: src/kani_proofs.rs must contain no TODO placeholders — the proof
/// body must be fully implemented.
#[test]
fn test_ac_001_no_todo_in_composed_harness() {
    let content = read_file("src/kani_proofs.rs");

    assert!(
        !content.contains("TODO(S-4.04 step 4)"),
        "AC-001: src/kani_proofs.rs still contains 'TODO(S-4.04 step 4)' — \
         the proof body has not been implemented"
    );
    assert!(
        !content.contains("todo!("),
        "AC-001: src/kani_proofs.rs still contains a 'todo!(' macro — \
         the proof body has not been implemented"
    );
}

/// AC-001: `kani::unwind(N)` must appear with a literal positive integer N.
///
/// The stub uses `kani::unwind(SOME_BOUND)` — a non-numeric placeholder.
/// After step 4 the bound must be a concrete positive integer.
#[test]
fn test_ac_001_has_real_unwind_bound() {
    let content = read_file("src/kani_proofs.rs");

    // Find all occurrences of `kani::unwind(...)` and check that the argument
    // is a positive decimal integer.
    //
    // We scan for the pattern manually to avoid any regex dependency.
    let needle = "kani::unwind(";
    let mut found_numeric = false;
    let mut found_any = false;

    let mut remaining = content.as_str();
    while let Some(pos) = remaining.find(needle) {
        found_any = true;
        let after_paren = &remaining[pos + needle.len()..];
        // Collect the argument up to the closing ')'
        let end = after_paren
            .find(')')
            .expect("AC-001: malformed kani::unwind — no closing ')'");
        let arg = after_paren[..end].trim();

        // Arg must be a sequence of ASCII digits representing a value > 0
        if !arg.is_empty() && arg.chars().all(|c| c.is_ascii_digit()) {
            let n: u64 = arg.parse().unwrap_or(0);
            if n > 0 {
                found_numeric = true;
            }
        }

        remaining = &remaining[pos + needle.len()..];
    }

    assert!(
        found_any,
        "AC-001: src/kani_proofs.rs does not contain any 'kani::unwind(...)' \
         attribute — the composed proof must declare an explicit unwind bound"
    );
    assert!(
        found_numeric,
        "AC-001: src/kani_proofs.rs has 'kani::unwind(...)' but the argument \
         is not a positive integer literal (found a placeholder like SOME_BOUND \
         or zero). The unwind bound must be set to a concrete positive integer \
         before the proof is valid."
    );
}

// ---------------------------------------------------------------------------
// AC-002 — reviewer doc exists with all required sections
// ---------------------------------------------------------------------------

/// AC-002: docs/proofs/privacy-invariant.md must exist.
#[test]
fn test_ac_002_reviewer_doc_exists() {
    assert!(
        file_exists("docs/proofs/privacy-invariant.md"),
        "AC-002: reviewer doc docs/proofs/privacy-invariant.md does not exist"
    );
}

/// AC-002: the doc must contain all five required H2 headers.
#[test]
fn test_ac_002_doc_has_required_sections() {
    let content = read_file("docs/proofs/privacy-invariant.md");
    let lower = content.to_lowercase();

    let required: &[(&str, &str)] = &[
        ("## overview", "## Overview"),
        ("## the three component proofs", "## The three component proofs"),
        ("## the composed proof", "## The composed proof"),
        ("## what bounds remain", "## What bounds remain"),
        ("## how to run", "## How to run"),
    ];

    for (needle, display) in required {
        assert!(
            lower.contains(needle),
            "AC-002: docs/proofs/privacy-invariant.md is missing required \
             section '{display}'"
        );
    }
}

/// AC-002: the doc must mention all three component-proof stories.
#[test]
fn test_ac_002_doc_references_s_4_01_02_03() {
    let content = read_file("docs/proofs/privacy-invariant.md");

    for story in &["S-4.01", "S-4.02", "S-4.03"] {
        assert!(
            content.contains(story),
            "AC-002: docs/proofs/privacy-invariant.md does not reference \
             component-proof story {story} — the 'The three component proofs' \
             section must mention all three Wave-1 stories"
        );
    }
}

/// AC-002: the doc must mention the behavioral contract being formally verified.
#[test]
fn test_ac_002_doc_references_bc_5_02_003() {
    let content = read_file("docs/proofs/privacy-invariant.md");

    assert!(
        content.contains("BC-5.02.003"),
        "AC-002: docs/proofs/privacy-invariant.md does not reference \
         'BC-5.02.003' — the reviewer doc must identify the behavioral \
         contract that the composed proof formally verifies"
    );
}

/// AC-002: the doc must not contain TODO placeholders.
#[test]
fn test_ac_002_doc_has_no_todo_placeholders() {
    let content = read_file("docs/proofs/privacy-invariant.md");

    assert!(
        !content.contains("TODO(S-4.04 step 4)"),
        "AC-002: docs/proofs/privacy-invariant.md still contains \
         'TODO(S-4.04 step 4)' placeholders — the reviewer doc must be \
         fully written before this story is complete"
    );
}

// ---------------------------------------------------------------------------
// CI integration smoke test
// ---------------------------------------------------------------------------

/// CI smoke: .github/workflows/kani.yml must reference `composed_privacy_invariant`
/// so the proof is actually executed in the weekly CI run.
#[test]
fn test_kani_workflow_includes_composed_harness() {
    let content = read_file(".github/workflows/kani.yml");

    assert!(
        content.contains("composed_privacy_invariant"),
        "CI smoke: .github/workflows/kani.yml does not mention \
         'composed_privacy_invariant' — the composed harness must be wired \
         into the CI Kani workflow to provide ongoing proof coverage"
    );
}
