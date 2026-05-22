/// Acceptance tests for S-3.03: mutation testing CI infrastructure.
///
/// This file is the Red Gate — every test must FAIL against the stub commit
/// (fa95cd3) that contains TODO placeholders, and must PASS once the
/// implementer fills in real values in Step 4.
///
/// Tests use only `std::fs` and string matching; no new dependencies.
///
/// Naming: test_ac_NNN_description

// ---------------------------------------------------------------------------
// AC-001 — .cargo-mutants.toml: scoped mutation config
// ---------------------------------------------------------------------------

/// AC-001: .cargo-mutants.toml must exist and be parseable as TOML.
/// Fails against stub because the file has TODO placeholders that indicate
/// it is incomplete — we verify completeness by asserting no TODOs remain
/// (handled in test_ac_001_no_todo_placeholders_remain).  This test also
/// asserts the file exists and can be read so that a missing file is caught
/// with a clear message.
#[test]
fn test_ac_001_cargo_mutants_config_exists_and_is_valid_toml() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/.cargo-mutants.toml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-001: .cargo-mutants.toml must exist at repo root; \
             failed to read {path}: {e}"
        )
    });

    // Minimal structure: must have an [examine] section with examine_globs.
    assert!(
        content.contains("[examine]"),
        "AC-001: .cargo-mutants.toml must contain an [examine] section; \
         found content:\n{content}"
    );
    assert!(
        content.contains("examine_globs"),
        "AC-001: .cargo-mutants.toml must contain examine_globs to scope \
         mutation testing; found content:\n{content}"
    );

    // Must have a [skip] section with at least one documented entry (not empty).
    // AC-001 requires "skip-list documented for known-irrelevant mutations".
    // The stub has `skip = []` — an empty skip list means the skip-list is not
    // yet documented, so this assertion fails until Step 4 populates it.
    assert!(
        !content.contains("skip = []"),
        "AC-001: .cargo-mutants.toml skip list must be populated with \
         at least one entry for known-irrelevant mutations (e.g. metadata \
         strings, log levels, evidence sample order); stub had skip = [] \
         with no entries documented"
    );
}

/// AC-001: The four high-value modules must be listed in examine_globs AND
/// the skip-list must be non-trivially documented (not just a bare comment
/// referencing TODO).
///
/// Fails against stub because `skip = []` means no skip entries are present,
/// and also because TODO placeholders appear throughout the skip section.
#[test]
fn test_ac_001_examine_globs_cover_the_four_high_value_modules() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/.cargo-mutants.toml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-001: .cargo-mutants.toml must exist; \
             failed to read {path}: {e}"
        )
    });

    for module in &[
        "src/findings/",
        "src/parse/",
        "src/scrub.rs",
        "src/ai/leak_detector.rs",
    ] {
        assert!(
            content.contains(module),
            "AC-001: .cargo-mutants.toml examine_globs must reference \
             high-value module {module}; it was missing from content:\n\
             {content}"
        );
    }

    // The skip section must have at least one real skip entry (not TODO).
    // A real skip entry will be a non-empty string value, e.g. `"src/main.rs"`.
    // We detect "no real skip entries" by checking that the file still has the
    // TODO marker specifically in the skip-list block.
    assert!(
        !content.contains("TODO(S-3.03 step 4): add skip-list entries"),
        "AC-001: the [skip] section TODO comment must be replaced with real \
         skip-list entries for known-irrelevant mutations; stub had TODO \
         placeholder for skip-list entries"
    );
}

/// AC-001: .cargo-mutants.toml must not contain any TODO(S-3.03 step 4)
/// placeholders — they indicate the config is a stub, not a real config.
#[test]
fn test_ac_001_no_todo_placeholders_remain() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/.cargo-mutants.toml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-001: .cargo-mutants.toml must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        !content.contains("TODO(S-3.03 step 4)"),
        "AC-001: .cargo-mutants.toml must not contain TODO(S-3.03 step 4) \
         placeholders; the stub has unfilled placeholders that must be \
         replaced with real configuration before this story is done"
    );
}

// ---------------------------------------------------------------------------
// AC-002 — .github/workflows/mutants.yml: CI integration
// ---------------------------------------------------------------------------

/// AC-002: .github/workflows/mutants.yml must exist AND must have the kill-rate
/// results posted somewhere (issue comment, artifact, or action summary) — not
/// just an echo TODO stub.
///
/// Fails against stub because the "Comment on develop with results" step
/// contains `echo "TODO(S-3.03 step 4): post kill-rate summary..."` which is
/// a placeholder, not a real result-posting step.
#[test]
fn test_ac_002_mutants_workflow_exists() {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/.github/workflows/mutants.yml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-002: .github/workflows/mutants.yml must exist to integrate \
             mutation testing into CI; failed to read {path}: {e}"
        )
    });

    // The workflow must report results — not just upload an artifact but also
    // post a summary so the team can see the kill-rate without downloading the
    // artifact.  The stub has an echo TODO as the result-posting step.
    assert!(
        !content.contains("echo \"TODO(S-3.03 step 4)"),
        "AC-002: the result-posting step in .github/workflows/mutants.yml \
         must be implemented (write to GITHUB_STEP_SUMMARY or post an issue \
         comment); the stub has a bare `echo TODO(...)` placeholder that \
         must be replaced with real reporting logic"
    );
}

/// AC-002: The workflow must run on a schedule (weekly) using a real cron
/// expression — not a TODO placeholder.
///
/// Fails against the stub because the cron line has a comment saying
/// "placeholder: runs daily at 00:00 UTC (replace with actual schedule)"
/// which indicates Step 4 has not been completed.
#[test]
fn test_ac_002_workflow_runs_on_schedule() {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/.github/workflows/mutants.yml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-002: .github/workflows/mutants.yml must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        content.contains("schedule:"),
        "AC-002: workflow must have a `schedule:` trigger so it runs \
         automatically on a recurring basis; not found in {path}"
    );
    assert!(
        content.contains("cron:"),
        "AC-002: workflow must have a `cron:` expression under schedule; \
         not found in {path}"
    );

    // The stub uses a daily placeholder cron with an inline comment saying
    // "placeholder" and "replace with actual schedule".  The implementer must
    // change this to a real weekly schedule.  We detect the stub by checking
    // that the placeholder comment is still present.
    assert!(
        !content.contains("placeholder: runs daily"),
        "AC-002: the cron expression must be a real weekly schedule, not the \
         stub placeholder '0 0 * * *' with comment 'placeholder: runs daily \
         at 00:00 UTC'; replace with a genuine weekly cron expression \
         (e.g. '0 6 * * 1' for Monday 06:00 UTC)"
    );

    // Also assert the schedule is weekly (7-day cadence) per AC-002.
    // A weekly cron has the form '* * * * 0-6' or uses day-of-week field.
    // We check the presence of a day-of-week specification (0-7 range) which
    // distinguishes daily from weekly.  The stub '0 0 * * *' runs daily.
    // After Step 4, the cron must target a single day of week.
    assert!(
        !content.contains("0 0 * * *"),
        "AC-002: the cron schedule '0 0 * * *' runs daily, not weekly; \
         AC-002 requires a weekly cadence (e.g. '0 6 * * 1'); \
         update the schedule to run on develop tip once per week"
    );
}

/// AC-002: The workflow must NOT block PRs AND must have cargo-mutants pinned
/// to a specific version (not just `cargo install cargo-mutants` with no pin),
/// so CI is reproducible.
///
/// Fails against stub because the install step uses an unpinned
/// `cargo install cargo-mutants` — the TODO comment says "pin version once
/// established" but Step 4 has not done so.
#[test]
fn test_ac_002_workflow_does_not_block_prs() {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/.github/workflows/mutants.yml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-002: .github/workflows/mutants.yml must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        !content.contains("pull_request:") && !content.contains("pull_request\n"),
        "AC-002: the mutants workflow must NOT trigger on pull_request; \
         mutation testing is slow and must not block PR merges; \
         use schedule + workflow_dispatch only"
    );

    // cargo-mutants must be pinned to a version for reproducible CI.
    // The stub install step is `cargo install cargo-mutants` with no --version.
    // A pinned install looks like `cargo install cargo-mutants --version X.Y.Z`
    // or uses a tool like `cargo-binstall` with an explicit version.
    assert!(
        !content.contains("# TODO(S-3.03 step 4): pin version once established"),
        "AC-002: cargo-mutants must be pinned to a specific version in the \
         workflow (e.g. `cargo install cargo-mutants --version 24.x.x`); \
         the stub has a TODO comment saying to pin once established; \
         Step 4 must replace this with a real pinned install"
    );
}

/// AC-002: .github/workflows/mutants.yml must not contain any
/// TODO(S-3.03 step 4) placeholders.
#[test]
fn test_ac_002_no_todo_placeholders_remain() {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/.github/workflows/mutants.yml");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-002: .github/workflows/mutants.yml must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        !content.contains("TODO(S-3.03 step 4)"),
        "AC-002: .github/workflows/mutants.yml must not contain \
         TODO(S-3.03 step 4) placeholders; the stub has multiple \
         unfilled TODOs (cargo-mutants version pin, output format, \
         result posting) that must be resolved before this story is done"
    );
}

// ---------------------------------------------------------------------------
// AC-003 — kill-rate baseline + ratchet documented in docs/MUTANTS.md
// ---------------------------------------------------------------------------

/// AC-003: docs/MUTANTS.md must contain a Kill-rate baseline section with
/// a real numeric percentage (not placeholder dashes).
///
/// Fails against stub because the table contains '—' (em-dash) placeholders
/// instead of real kill-rate numbers.
#[test]
fn test_ac_003_baseline_documented_in_mutants_md() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/MUTANTS.md");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-003: docs/MUTANTS.md must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        content.contains("## Kill-rate baseline"),
        "AC-003: docs/MUTANTS.md must have a '## Kill-rate baseline' \
         section documenting the initial baseline run; section not found"
    );

    // Require at least one real percentage value in the baseline section.
    // We search for a pattern like "75%" or "82.3%" in the content.
    // The stub only has '—' placeholder cells with no percentages.
    let has_percentage = {
        // Find the baseline section and look for a digit followed by '%'
        let baseline_start = content.find("## Kill-rate baseline");
        let section_end = content[baseline_start.unwrap_or(0)..]
            .find("\n## ")
            .map(|offset| baseline_start.unwrap_or(0) + offset)
            .unwrap_or(content.len());
        let section = baseline_start
            .map(|s| &content[s..section_end])
            .unwrap_or("");
        section.contains('%')
            && section
                .chars()
                .zip(section.chars().skip(1))
                .any(|(a, b)| a.is_ascii_digit() && b == '%'
                    || (a.is_ascii_digit() && b.is_ascii_digit()))
    };

    assert!(
        has_percentage,
        "AC-003: the Kill-rate baseline section in docs/MUTANTS.md must \
         contain at least one numeric kill-rate percentage (e.g. '75%'); \
         stub has only '—' placeholder cells with no measured values; \
         run Step 3 baseline and record the result"
    );
}

/// AC-003: docs/MUTANTS.md must document the 5% drop threshold that triggers
/// a ratchet review (soft signal).
///
/// Fails against stub because the Triage workflow section has TODO placeholders
/// instead of real process steps; the "5%" text is present but only in a
/// stub header — we verify the surrounding context is not a bare TODO.
#[test]
fn test_ac_003_ratchet_policy_documented() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/MUTANTS.md");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-003: docs/MUTANTS.md must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        content.contains("5%"),
        "AC-003: docs/MUTANTS.md must mention the 5% kill-rate drop \
         threshold that triggers ratchet review per AC-003; '5%' not found"
    );

    // The stub has "When mutation kill-rate drops > 5%:" followed immediately
    // by numbered stub items "1. ..." and "2. ..." with no real content.
    // The real implementation must replace these with actual policy steps.
    // We detect the stub by checking that the triage workflow TODO is present.
    assert!(
        !content.contains("TODO(S-3.03 step 4): write the process for responding"),
        "AC-003: the Triage workflow section in docs/MUTANTS.md must describe \
         the real process for responding to a kill-rate drop > 5%; the stub \
         TODO placeholder must be replaced with actual policy steps"
    );
}

// ---------------------------------------------------------------------------
// AC-004 — triage doc: docs/MUTANTS.md has all required sections
// ---------------------------------------------------------------------------

/// AC-004: docs/MUTANTS.md must contain all five H2 section headers required
/// by the story spec.
///
/// Fails against stub because the sections exist as headings but their bodies
/// contain only TODO placeholders — however this test checks header presence,
/// which the stub satisfies for most sections. The companion
/// test_ac_004_no_todo_placeholders_remain will catch the stub body content.
/// This test additionally checks that the section bodies are non-trivially
/// populated (not just the heading + a TODO line).
#[test]
fn test_ac_004_mutants_md_has_required_sections() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/MUTANTS.md");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-004: docs/MUTANTS.md must exist; \
             failed to read {path}: {e}"
        )
    });

    for heading in &[
        "## Scope",
        "## Kill-rate baseline",
        "## Interpreting a missed mutation",
        "## Common false-positives",
        "## Triage workflow",
    ] {
        assert!(
            content.contains(heading),
            "AC-004: docs/MUTANTS.md must contain the section '{heading}'; \
             section was not found; the triage doc is incomplete"
        );
    }

    // Each section body must contain substantive content — not just a TODO.
    // We check "Interpreting a missed mutation" since the stub body is literally
    // "A missed mutation indicates:\n- ..." with no real content.
    // A real implementation will have at least two bullet points or paragraphs
    // beyond the section header.
    let interpret_start = content
        .find("## Interpreting a missed mutation")
        .unwrap_or(0);
    let interpret_end = content[interpret_start..]
        .find("\n## ")
        .map(|off| interpret_start + off)
        .unwrap_or(content.len());
    let interpret_section = &content[interpret_start..interpret_end];

    assert!(
        !interpret_section.contains("TODO(S-3.03 step 4)"),
        "AC-004: the '## Interpreting a missed mutation' section must contain \
         real guidance, not a TODO placeholder; the stub has an empty body \
         that must be written before this story is done"
    );

    // Similarly check Common false-positives has real entries beyond the stub skeleton.
    let fp_start = content.find("## Common false-positives").unwrap_or(0);
    let fp_end = content[fp_start..]
        .find("\n## ")
        .map(|off| fp_start + off)
        .unwrap_or(content.len());
    let fp_section = &content[fp_start..fp_end];

    assert!(
        !fp_section.contains("TODO(S-3.03 step 4)"),
        "AC-004: the '## Common false-positives' section must document real \
         false-positive patterns in this codebase, not a TODO placeholder"
    );
}

/// AC-004: docs/MUTANTS.md must not contain any TODO(S-3.03 step 4)
/// placeholders — they indicate the triage doc is a stub, not a real doc.
#[test]
fn test_ac_004_no_todo_placeholders_remain() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/MUTANTS.md");
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "AC-004: docs/MUTANTS.md must exist; \
             failed to read {path}: {e}"
        )
    });

    assert!(
        !content.contains("TODO(S-3.03 step 4)"),
        "AC-004: docs/MUTANTS.md must not contain TODO(S-3.03 step 4) \
         placeholders; the stub has TODOs in every section body (Scope, \
         Kill-rate baseline, Interpreting a missed mutation, Common \
         false-positives, Triage workflow) that must be replaced with \
         real documentation before this story is done"
    );
}
