//! Acceptance tests for S-3.04: Fuzz harnesses for all parsers.
//!
//! Covers BC-1.02.001..005. All tests use only std::fs, std::path, and
//! string-matching primitives — zero new dependencies.
//!
//! Every test MUST fail against the stub commit (467acec) and pass after
//! Step 4 implementation.

use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Root of the worktree, derived from CARGO_MANIFEST_DIR so the tests work
/// regardless of the cwd the test runner picks.
fn worktree_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is set to the package root by cargo test.
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read_file_to_string(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("could not read {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// AC-001: fuzz/ directory + harnesses
// BC-1.02.001 — fuzz package Cargo.toml lists exactly 6 named binaries
// ---------------------------------------------------------------------------

#[test]
fn test_bc_1_02_001_ac001_fuzz_cargo_toml_exists_and_lists_six_binaries() {
    let path = worktree_root().join("fuzz/Cargo.toml");
    assert!(
        path.exists(),
        "AC-001: fuzz/Cargo.toml must exist (BC-1.02.001)"
    );

    let content = read_file_to_string(&path);

    // Count [[bin]] sections.
    let bin_count = content.matches("[[bin]]").count();
    assert_eq!(
        bin_count, 6,
        "AC-001: fuzz/Cargo.toml must contain exactly 6 [[bin]] entries (BC-1.02.001); found {}",
        bin_count
    );

    // Verify each required binary name is present.
    let required = [
        "parse_modbus",
        "parse_enip",
        "parse_s7comm",
        "parse_dhcp",
        "parse_dnp3",
        "scrub_text",
    ];
    for name in &required {
        assert!(
            content.contains(&format!("name = \"{}\"", name)),
            "AC-001: fuzz/Cargo.toml must contain [[bin]] named \"{}\" (BC-1.02.001)",
            name
        );
    }
}

// BC-1.02.001 — each harness source file exists
#[test]
fn test_bc_1_02_001_ac001_each_harness_file_exists() {
    let base = worktree_root().join("fuzz/fuzz_targets");
    let required = [
        "parse_modbus.rs",
        "parse_enip.rs",
        "parse_s7comm.rs",
        "parse_dhcp.rs",
        "parse_dnp3.rs",
        "scrub_text.rs",
    ];
    for name in &required {
        let path = base.join(name);
        assert!(
            path.exists(),
            "AC-001: fuzz/fuzz_targets/{} must exist (BC-1.02.001)",
            name
        );
    }
}

// BC-1.02.001 — each harness imports the right symbol AND bounds input to 64 KB (EC-001)
#[test]
fn test_bc_1_02_001_ac001_each_harness_calls_parser_and_bounds_input() {
    let base = worktree_root().join("fuzz/fuzz_targets");

    // (harness_file, required_module_fragment)
    let parsers: &[(&str, &str)] = &[
        ("parse_modbus.rs", "otsniff::parse::modbus::"),
        ("parse_enip.rs", "otsniff::parse::enip::"),
        ("parse_s7comm.rs", "otsniff::parse::s7comm::"),
        ("parse_dhcp.rs", "otsniff::parse::dhcp::"),
        ("parse_dnp3.rs", "otsniff::parse::dnp3::"),
        ("scrub_text.rs", "otsniff_privacy::scrub_text"),
    ];

    for (filename, module) in parsers {
        let path = base.join(filename);
        let content = read_file_to_string(&path);

        assert!(
            content.contains(module),
            "AC-001: {filename} must import {module} (BC-1.02.001 — parser must be exercised)"
        );

        // EC-001: input must be bounded at 64 KB.
        // Accept any of the three equivalent literals the implementer may choose.
        let bounds_input = content.contains("65536")
            || content.contains("64 * 1024")
            || content.contains("64_000");
        assert!(
            bounds_input,
            "AC-001: {filename} must bound input to 64 KB per EC-001 \
             (search for '65536', '64 * 1024', or '64_000' in the file body)"
        );
    }
}

// BC-1.02.001 — no TODO placeholders left in harness files after Step 4
#[test]
fn test_bc_1_02_001_ac001_no_todo_placeholders_in_fuzz_targets() {
    let base = worktree_root().join("fuzz/fuzz_targets");
    let files = [
        "parse_modbus.rs",
        "parse_enip.rs",
        "parse_s7comm.rs",
        "parse_dhcp.rs",
        "parse_dnp3.rs",
        "scrub_text.rs",
    ];
    for name in &files {
        let path = base.join(name);
        let content = read_file_to_string(&path);
        assert!(
            !content.contains("TODO(S-3.04 step 4)"),
            "AC-001: fuzz/fuzz_targets/{name} must not contain 'TODO(S-3.04 step 4)' \
             — implementation is incomplete (BC-1.02.001)"
        );
    }
}

// BC-1.02.001 — no TODO placeholders in fuzz/Cargo.toml after Step 4
#[test]
fn test_bc_1_02_001_ac001_no_todo_placeholders_in_fuzz_cargo_toml() {
    let path = worktree_root().join("fuzz/Cargo.toml");
    let content = read_file_to_string(&path);
    assert!(
        !content.contains("TODO(S-3.04 step 4)"),
        "AC-001: fuzz/Cargo.toml must not contain 'TODO(S-3.04 step 4)' \
         — implementation is incomplete (BC-1.02.001)"
    );
}

// ---------------------------------------------------------------------------
// AC-002: CI integration on slow schedule
// BC-1.02.002 — .github/workflows/fuzz.yml exists
// ---------------------------------------------------------------------------

#[test]
fn test_bc_1_02_002_ac002_fuzz_workflow_exists() {
    let path = worktree_root().join(".github/workflows/fuzz.yml");
    assert!(
        path.exists(),
        "AC-002: .github/workflows/fuzz.yml must exist (BC-1.02.002)"
    );
}

// BC-1.02.002 — workflow runs on weekly schedule, NOT on pull_request
#[test]
fn test_bc_1_02_002_ac002_workflow_runs_weekly_not_pr() {
    let path = worktree_root().join(".github/workflows/fuzz.yml");
    let content = read_file_to_string(&path);

    assert!(
        content.contains("schedule:"),
        "AC-002: fuzz.yml must have a 'schedule:' trigger (BC-1.02.002)"
    );
    assert!(
        content.contains("cron:"),
        "AC-002: fuzz.yml must have a 'cron:' entry under schedule (BC-1.02.002)"
    );

    // A real cron expression has at least 5 fields; ensure the TODO placeholder
    // cron is not the only value present.  We check that a digit-containing
    // cron expression exists (i.e., "0 2 * * 0" style — not just the key word).
    let has_real_cron = content
        .lines()
        .filter(|l| l.trim_start().starts_with("- cron:"))
        .any(|l| {
            // Strip key and surrounding quotes/whitespace, then check for digits
            let val = l.split_once("cron:").map(|x| x.1).unwrap_or("").trim();
            val.chars().any(|c| c.is_ascii_digit())
        });
    assert!(
        has_real_cron,
        "AC-002: fuzz.yml cron: value must be a real schedule expression (BC-1.02.002)"
    );

    assert!(
        !content.contains("pull_request:"),
        "AC-002: fuzz.yml must NOT have a 'pull_request:' trigger — \
         fuzz runs on slow schedule only, not on every PR (BC-1.02.002)"
    );
}

// BC-1.02.002 — workflow runs each harness for 60 seconds and matrix lists all 6
#[test]
fn test_bc_1_02_002_ac002_workflow_runs_each_harness_60_seconds() {
    let path = worktree_root().join(".github/workflows/fuzz.yml");
    let content = read_file_to_string(&path);

    assert!(
        content.contains("max_total_time=60"),
        "AC-002: fuzz.yml must pass '-max_total_time=60' to the libFuzzer runner (BC-1.02.002)"
    );

    // All 6 harness names must appear in the workflow matrix.
    let harnesses = [
        "parse_modbus",
        "parse_enip",
        "parse_s7comm",
        "parse_dhcp",
        "parse_dnp3",
        "scrub_text",
    ];
    for name in &harnesses {
        assert!(
            content.contains(name),
            "AC-002: fuzz.yml matrix must list harness '{name}' (BC-1.02.002)"
        );
    }
}

// BC-1.02.002 — workflow uploads crash artifacts
#[test]
fn test_bc_1_02_002_ac002_workflow_uploads_crash_artifacts() {
    let path = worktree_root().join(".github/workflows/fuzz.yml");
    let content = read_file_to_string(&path);

    assert!(
        content.contains("upload-artifact"),
        "AC-002: fuzz.yml must have an 'upload-artifact' step (BC-1.02.002)"
    );
    assert!(
        content.contains("fuzz/artifacts/"),
        "AC-002: fuzz.yml upload-artifact step must reference 'fuzz/artifacts/' (BC-1.02.002)"
    );
}

// BC-1.02.002 — no TODO placeholders remain in workflow after Step 4
#[test]
fn test_bc_1_02_002_ac002_no_todo_placeholders_remain() {
    let path = worktree_root().join(".github/workflows/fuzz.yml");
    let content = read_file_to_string(&path);

    assert!(
        !content.contains("TODO(S-3.04 step 4)"),
        "AC-002: fuzz.yml must not contain 'TODO(S-3.04 step 4)' \
         — implementation is incomplete (BC-1.02.002)"
    );
}

// ---------------------------------------------------------------------------
// AC-003: corpus seeding
// BC-1.02.003 — seed policy documented or directories seeded
// ---------------------------------------------------------------------------

#[test]
fn test_bc_1_02_003_ac003_corpus_seed_doc_or_setup_present() {
    let root = worktree_root();

    // Acceptable evidence (any one suffices):
    //   1. fuzz/corpus/<harness>/ directories exist
    //   2. workflow step seeds from tests/fixtures/
    //   3. fuzz/README.md documents the seeding policy with the word "corpus"

    let corpus_dirs_exist = {
        let corpus_base = root.join("fuzz/corpus");
        corpus_base.exists()
            && fs::read_dir(&corpus_base)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false)
    };

    let workflow_seeds_corpus = {
        let wf_path = root.join(".github/workflows/fuzz.yml");
        wf_path.exists()
            && read_file_to_string(&wf_path)
                .to_lowercase()
                .contains("corpus")
    };

    let readme_documents_corpus = {
        let readme = root.join("fuzz/README.md");
        readme.exists()
            && read_file_to_string(&readme)
                .to_lowercase()
                .contains("corpus")
    };

    assert!(
        corpus_dirs_exist || workflow_seeds_corpus || readme_documents_corpus,
        "AC-003: corpus seeding policy must be established by one of: \
         (a) fuzz/corpus/<harness>/ seed directories, \
         (b) a workflow step referencing 'corpus', or \
         (c) fuzz/README.md documenting the corpus seeding policy. \
         None of these were found. (BC-1.02.003)"
    );
}

// ---------------------------------------------------------------------------
// AC-004: regression mode
// BC-1.02.004 — tests/fuzz_regressions.rs exists
// ---------------------------------------------------------------------------

#[test]
fn test_bc_1_02_004_ac004_fuzz_regressions_test_exists() {
    let path = worktree_root().join("tests/fuzz_regressions.rs");
    assert!(
        path.exists(),
        "AC-004: tests/fuzz_regressions.rs must exist (BC-1.02.004)"
    );
}

// BC-1.02.004 — artifact walk is implemented (not a TODO stub)
#[test]
fn test_bc_1_02_004_ac004_fuzz_regressions_test_walks_artifacts() {
    let path = worktree_root().join("tests/fuzz_regressions.rs");
    let content = read_file_to_string(&path);

    assert!(
        content.contains("fuzz/artifacts"),
        "AC-004: tests/fuzz_regressions.rs must reference 'fuzz/artifacts' \
         to walk crash reproducers (BC-1.02.004)"
    );

    // The test function body must not contain the stub placeholder.
    // We look inside the first fn body after the function signature line.
    // A simple approach: find the TODO inside a fn block.
    // We check the whole file for the stub marker inside a fn body by confirming
    // the marker is absent from the file entirely after the doc-comment header.
    let body_start = content
        .find("fn fuzz_artifacts_dont_panic")
        .unwrap_or(content.len());
    let body = &content[body_start..];
    assert!(
        !body.contains("TODO(S-3.04 step 4)"),
        "AC-004: tests/fuzz_regressions.rs::fuzz_artifacts_dont_panic must not contain \
         'TODO(S-3.04 step 4)' — the artifact walk must be implemented (BC-1.02.004)"
    );
}

// BC-1.02.005 — regression test mentions each parser module in executable code
// (string literals used to look up artifact directories), not just comments.
#[test]
fn test_bc_1_02_005_ac004_fuzz_regressions_test_handles_each_parser() {
    let path = worktree_root().join("tests/fuzz_regressions.rs");
    let content = read_file_to_string(&path);

    // Each harness directory name must appear as a quoted string literal in the
    // source so the artifact walk can locate it.  Stub comment lines that
    // mention harness names (e.g. "// (parse_modbus, ...)") are stripped before
    // the search so only executable code references count.
    let non_comment_lines: String = content
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n");

    // The harness directory names must appear as quoted string literals.
    let harness_names = [
        "parse_modbus",
        "parse_enip",
        "parse_s7comm",
        "parse_dhcp",
        "parse_dnp3",
        "scrub_text",
    ];
    for name in &harness_names {
        let quoted = format!("\"{}\"", name);
        assert!(
            non_comment_lines.contains(&quoted),
            "AC-004: tests/fuzz_regressions.rs must contain the string literal {quoted} \
             in executable code so the artifact walk dispatches to the '{name}' directory. \
             Comment-only mentions do not satisfy this contract. (BC-1.02.005)"
        );
    }
}
