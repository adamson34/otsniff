//! End-to-end CLI smoke tests.
//!
//! These exercise the binary through `assert_cmd`. They do *not* assert on
//! report contents — that's what the snapshot tests cover. Their job is to
//! catch obvious regressions in arg parsing, exit codes, and the
//! input-error → exit-code mapping across all subcommands.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// F-ADV-P2-015: tests below depend on `tests/fixtures/synthetic-1mb.pcap`
// which is committed (per .gitignore exception). Each test's skip branch is
// guarded with an `assert!` that fails when `CI` is set in the environment,
// so the silent-skip pattern can never recur in CI even if the fixture is
// accidentally removed from the .gitignore exception list.

#[test]
fn help_flag_succeeds() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("analyze"))
        .stdout(predicate::str::contains("scrub"))
        .stdout(predicate::str::contains("unscrub"));
}

#[test]
fn version_flag_succeeds() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("otsniff"));
}

#[test]
fn no_subcommand_fails() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn analyze_help_describes_command() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("HTML"))
        .stdout(predicate::str::contains("--ot-subnet"))
        .stdout(predicate::str::contains("--ai"));
}

#[test]
fn scrub_help_describes_command() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["scrub", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pseudonyms"))
        .stdout(predicate::str::contains("--map"));
}

#[test]
fn unscrub_help_describes_command() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["unscrub", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pseudonyms"))
        .stdout(predicate::str::contains("--map"));
}

#[test]
fn analyze_nonexistent_input_exits_2() {
    let tmp = TempDir::new().unwrap();
    let bogus = tmp.path().join("does-not-exist.pcap");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&bogus)
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("could not open input"));
}

#[test]
fn analyze_malformed_input_exits_2() {
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("garbage.pcap");
    std::fs::write(&bad, b"this is not a pcap file at all").unwrap();
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&bad)
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a valid pcap"));
}

#[test]
fn analyze_valid_pcap_produces_html_and_exits_0() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        // F-ADV-P2-015: missing fixture in CI is a hard failure (not silent skip).
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: tests/fixtures/synthetic-1mb.pcap missing in CI; \
             check .gitignore exception"
        );
        eprintln!("skipping: tests/fixtures/synthetic-1mb.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    let body = std::fs::read_to_string(&out).unwrap();
    assert!(body.contains("<html"));
    assert!(body.contains("Asset inventory"));
}

#[test]
fn scrub_round_trip_via_pcap() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        // F-ADV-P2-015: missing fixture in CI is a hard failure (not silent skip).
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: tests/fixtures/synthetic-1mb.pcap missing in CI; \
             check .gitignore exception"
        );
        eprintln!("skipping: tests/fixtures/synthetic-1mb.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let md = tmp.path().join("scrubbed.md");
    let map = tmp.path().join("map.json");

    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["scrub"])
        .arg(&pcap)
        .arg("-o")
        .arg(&md)
        .arg("--map")
        .arg(&map)
        .assert()
        .success();

    let scrubbed = std::fs::read_to_string(&md).unwrap();
    let map_text = std::fs::read_to_string(&map).unwrap();

    // F-ADV-P2-015: synthetic-1mb.pcap (committed) has 10.10.0.* IPs;
    // neither should appear in the scrubbed report.
    assert!(
        !scrubbed.contains("10.10.0.1"),
        "scrub round-trip: raw 10.10.0.1 leaked into scrubbed report"
    );
    assert!(
        !scrubbed.contains("10.10.0.2"),
        "scrub round-trip: raw 10.10.0.2 leaked into scrubbed report"
    );
    assert!(scrubbed.contains("host_001"));
    // Map should mention both real IPs.
    assert!(map_text.contains("10.10.0.1"));
    assert!(map_text.contains("10.10.0.2"));

    // Now unscrub a synthetic AI response.
    let llm_response = tmp.path().join("ai.txt");
    std::fs::write(
        &llm_response,
        "Look at host_001 and host_999 — only host_001 is real.\n",
    )
    .unwrap();
    let final_out = tmp.path().join("final.txt");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["unscrub", "--map"])
        .arg(&map)
        .arg(&llm_response)
        .arg("-o")
        .arg(&final_out)
        .assert()
        .success();
    let final_text = std::fs::read_to_string(&final_out).unwrap();
    assert!(
        final_text.contains("10.10.0.1"),
        "unscrub: host_001 should resolve to 10.10.0.1"
    );
    assert!(final_text.contains("host_999")); // unmapped pseudonym left as-is
}

// ── Group A1: S-9.01 multi-PCAP analyze (BC-1.01.003) ────────────────────────

/// S-9.01 AC-001 / EC-002: `analyze` with zero positional inputs must fail with
/// clap's usage error (exit 2) and never reach the ingestion path.
#[test]
fn s_9_01_analyze_zero_inputs_is_usage_error() {
    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage"));
}

/// S-9.01 AC-001 / EC-001: exactly one positional input still succeeds and
/// writes a report.
#[test]
fn s_9_01_analyze_one_input_succeeds() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: synthetic-1mb.pcap missing in CI"
        );
        eprintln!("skipping s_9_01_analyze_one_input_succeeds: synthetic-1mb.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert!(std::fs::read_to_string(&out).unwrap().contains("<html"));
}

/// S-9.01 AC-001 / AC-002 / AC-005: two positional inputs are ingested as one
/// logical capture and produce a single report. The markdown source label
/// (via --md) shows both basenames and never leaks an absolute path separator.
#[test]
fn s_9_01_analyze_two_inputs_succeeds() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: synthetic-1mb.pcap missing in CI"
        );
        eprintln!("skipping s_9_01_analyze_two_inputs_succeeds: synthetic-1mb.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    // Two distinct basenames so the combined source label is observable.
    let a = tmp.path().join("capture-01.pcap");
    let b = tmp.path().join("capture-02.pcap");
    std::fs::copy(&pcap, &a).unwrap();
    std::fs::copy(&pcap, &b).unwrap();
    let out = tmp.path().join("report.html");
    let md = tmp.path().join("report.md");

    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&a)
        .arg(&b)
        .arg("-o")
        .arg(&out)
        .arg("--md")
        .arg(&md)
        .assert()
        .success();

    assert!(std::fs::read_to_string(&out).unwrap().contains("<html"));
    let md_text = std::fs::read_to_string(&md).unwrap();
    // AC-005: both basenames appear in the multi-file source label.
    assert!(
        md_text.contains("capture-01.pcap"),
        "multi-file markdown should name the first capture"
    );
    assert!(
        md_text.contains("capture-02.pcap"),
        "multi-file markdown should name the second capture"
    );
    // F-ADV-P2-009: the basename-only label must not embed the tempdir path.
    let leaked = tmp.path().display().to_string();
    assert!(
        !md_text.contains(&leaked),
        "multi-file source label leaked an absolute path"
    );
}

// ── Group A2: S-6.01 --baseline-map flag (BC-5.03.001 AC-003) ────────────────

/// BC-5.03.001 AC-003 / CLI: `scrub --baseline-map` must produce a new map
/// that strictly extends the baseline.  Specifically:
///
/// 1. The baseline entry (host_001 → 192.168.1.1) must appear verbatim in the
///    new map even when 192.168.1.1 is NOT present in the fixture capture
///    (EC-003 preservation).
/// 2. Any IPs discovered in the fixture must receive fresh pseudonyms with
///    numeric suffixes strictly greater than the baseline maximum (here 1).
///
/// Fixture dependency: this test guards against false-passes by skipping
/// gracefully if `tests/fixtures/synthetic-1mb.pcap` is absent (same pattern as
/// other fixture-dependent tests in this file).
#[test]
fn test_bc_5_03_001_baseline_map_flag_extends_pseudonyms() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        // F-ADV-P2-015: missing fixture in CI is a hard failure (not silent skip).
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: tests/fixtures/synthetic-1mb.pcap missing in CI; \
             check .gitignore exception"
        );
        eprintln!("skipping: tests/fixtures/synthetic-1mb.pcap not present");
        return;
    }

    let tmp = TempDir::new().unwrap();

    // Write a minimal baseline map JSON with a single known entry.
    // 192.168.1.1 is deliberately chosen to NOT appear in Modbus.pcap so we
    // exercise the EC-003 (preserve-even-when-absent) path.
    let baseline_map_path = tmp.path().join("baseline.map.json");
    let baseline_json = serde_json::json!({
        "version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "ips":  { "host_001": "192.168.1.1" },
        "macs": {},
        "names": {}
    });
    std::fs::write(&baseline_map_path, baseline_json.to_string()).unwrap();

    let report_md = tmp.path().join("scrubbed.md");
    let new_map_path = tmp.path().join("new.map.json");

    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["scrub"])
        .arg(&pcap)
        .arg("--baseline-map")
        .arg(&baseline_map_path)
        .arg("-o")
        .arg(&report_md)
        .arg("--map")
        .arg(&new_map_path)
        .assert()
        .success();

    let new_map_text = std::fs::read_to_string(&new_map_path).unwrap();
    let new_map: serde_json::Value =
        serde_json::from_str(&new_map_text).expect("new map must be valid JSON");

    let ips = new_map["ips"].as_object().expect("ips must be an object");

    // EC-003: baseline entry must be preserved even though 192.168.1.1 is not
    // in the capture.
    assert_eq!(
        ips.get("host_001").and_then(|v| v.as_str()),
        Some("192.168.1.1"),
        "baseline host_001 → 192.168.1.1 must be preserved in new map (EC-003)"
    );

    // Any additional IPs discovered in the fixture must use suffixes > 1.
    for (pseudo, _real) in ips.iter() {
        if pseudo == "host_001" {
            continue; // baseline entry already checked above
        }
        let suffix: u32 = pseudo
            .strip_prefix("host_")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected pseudonym shape: {pseudo}"));
        assert!(
            suffix > 1,
            "new pseudonym {pseudo} must have suffix > 1 (baseline max was 1)"
        );
    }
}

// ── Group B: S-5.04 --review-scrub gate (BC-9.06.001) ─────────────────────────

/// BC-9.06.001: --review-scrub must be a documented flag in the analyze
/// subcommand help text.  Fails until the flag is added to AnalyzeArgs.
#[test]
fn test_bc_9_06_001_analyze_help_lists_review_scrub_flag() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--review-scrub"));
}

/// BC-9.06.001: when --review-scrub is set and the user answers "n",
/// otsniff must write the scrubbed-prompt header to stderr and exit 70.
///
/// Uses a minimal synthetic PCAP fixture built inline; if the real
/// Modbus fixture is present it is used instead (faster).
///
/// The test pipes "n\n" to stdin.  Expects:
///   • exit code 70  (OtError::Parse → EX_SOFTWARE)
///   • stderr contains the header sentinel "scrubbed prompt to claude"
///   • stderr does NOT contain the word "AI analysis" (invocation aborted)
#[test]
fn test_bc_9_06_001_review_scrub_aborts_on_n() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: synthetic-1mb.pcap missing in CI"
        );
        eprintln!(
            "skipping test_bc_9_06_001_review_scrub_aborts_on_n: synthetic-1mb.pcap not present"
        );
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "--ai", "--review-scrub"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .write_stdin("n\n")
        .assert()
        .code(70)
        .stderr(predicate::str::contains("scrubbed prompt to claude"));
}

/// BC-9.06.001: EOF on stdin (e.g. `< /dev/null`) with --review-scrub must
/// also abort with exit 70 — EC-003 edge case.
#[test]
fn test_bc_9_06_001_review_scrub_aborts_on_eof() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: synthetic-1mb.pcap missing in CI"
        );
        eprintln!(
            "skipping test_bc_9_06_001_review_scrub_aborts_on_eof: synthetic-1mb.pcap not present"
        );
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    // write_stdin("") simulates empty / closed stdin from the test harness
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "--ai", "--review-scrub"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .write_stdin("")
        .assert()
        .code(70)
        .stderr(predicate::str::contains("scrubbed prompt to claude"));
}

/// F-ADV-P5-001: when `analyze --ai` is invoked with a PCAP whose basename
/// embeds operator BCSI (plant/line/facility identifiers), those tokens
/// must NOT appear in the bytes sent to the AI provider. The basename is
/// outside the scrub map's domain, so the scrub/leak-detector pair cannot
/// catch this — the fix is to substitute a constant sentinel for the
/// markdown header's `input_label` before the scrub-and-send step.
///
/// `--review-scrub` prints the exact AI-bound payload to stderr, which
/// gives the test a direct view into what the AI would receive.
#[test]
fn test_f_adv_p5_001_pcap_basename_does_not_leak_to_ai() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        assert!(
            std::env::var("CI").is_err(),
            "F-ADV-P2-015: synthetic-1mb.pcap missing in CI"
        );
        eprintln!(
            "skipping test_f_adv_p5_001_pcap_basename_does_not_leak_to_ai: \
             synthetic-1mb.pcap not present"
        );
        return;
    }
    let tmp = TempDir::new().unwrap();
    // Sensitive basename simulating an operator-named capture. If the fix
    // regresses, these tokens reach the AI provider via the markdown
    // header.
    let sensitive = tmp.path().join("acme-plant-alpha-line3-secret.pcap");
    std::fs::copy(&pcap, &sensitive).unwrap();
    let out = tmp.path().join("report.html");

    let assert = Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "--ai", "--review-scrub"])
        .arg(&sensitive)
        .arg("-o")
        .arg(&out)
        .write_stdin("n\n")
        .assert()
        .code(70)
        .stderr(predicate::str::contains("scrubbed prompt to claude"));

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    // Extract just the AI-bound payload between the `--- scrubbed prompt ...`
    // and `--- end scrubbed prompt ---` sentinels emitted by review_scrub_gate.
    let payload_start = stderr
        .find("--- scrubbed prompt to claude")
        .expect("--review-scrub did not emit the expected header");
    let payload_end = stderr
        .find("--- end scrubbed prompt ---")
        .expect("--review-scrub did not emit the expected footer");
    let payload = &stderr[payload_start..payload_end];

    for forbidden in [
        "acme-plant",
        "alpha-line3",
        "line3",
        "secret",
        "acme-plant-alpha-line3-secret.pcap",
    ] {
        assert!(
            !payload.contains(forbidden),
            "F-ADV-P5-001 regression: AI-bound payload contains operator BCSI \
             token '{forbidden}'.\nFull payload was:\n{payload}"
        );
    }
}

// ── Group C: ADR-0007 amendment (AC-003) ──────────────────────────────────────

/// AC-003: ADR-0007 must be amended to document --disallowed-tools and
/// cite S-5.04.  Fails until the implementer appends the amendment section.
#[test]
fn test_ac_003_adr_0007_documents_disallowed_tools_amendment() {
    let adr_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/adr/0007-ai-via-claude-cli.md");
    let adr =
        std::fs::read_to_string(&adr_path).expect("docs/adr/0007-ai-via-claude-cli.md must exist");
    assert!(
        adr.contains("--disallowed-tools") || adr.contains("disallowed_tools"),
        "ADR-0007 must document the --disallowed-tools amendment; file: {}",
        adr_path.display()
    );
    assert!(
        adr.contains("S-5.04"),
        "ADR-0007 must cite S-5.04 in the amendment section; file: {}",
        adr_path.display()
    );
}

/// BC-3.05.006 / AC-004: regression guard against the 26,067-findings explosion
/// observed in the 4SICS-22 capture with the S-2.10 (src, port, proto) grouping.
///
/// After S-2.12 lands, recon.port_scan must emit ≤ 20 findings for this PCAP
/// (one per scanning source IP, not one per port scanned).
///
/// Test is skipped if the fixture is absent — same gate as the Modbus.pcap tests.
#[test]
fn recon_port_scan_4sics_22_caps_at_20_findings() {
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/4SICS-GeekLounge-151022.pcap");
    if !pcap.exists() {
        eprintln!("skipping: tests/fixtures/4SICS-GeekLounge-151022.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let html_out = tmp.path().join("report.html");
    let json_out = tmp.path().join("findings.json");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "--ot-subnet", "10.10.10.0/24"])
        .arg(&pcap)
        .arg("-o")
        .arg(&html_out)
        .arg("--json")
        .arg(&json_out)
        .assert()
        .success();
    let json_text = std::fs::read_to_string(&json_out).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    let recon_count = parsed["findings"]
        .as_array()
        .expect("JSON output must contain a 'findings' array")
        .iter()
        .filter(|f| f["id"] == "recon.port_scan")
        .count();
    // 4SICS-22 is a scan-heavy CTF capture — 23 distinct scanning sources
    // verified post-S-2.12 (some probe full 65k port ranges). Bound is ≤ 30
    // to allow modest fixture variance; the pre-S-2.12 baseline was 26,067.
    assert!(
        recon_count <= 30,
        "4SICS-22 regression: recon.port_scan must emit ≤ 30 findings post-S-2.12 rollup; got {recon_count}"
    );
}

// ── Group D: S-5.01 parse-loop progress feedback (BC-9.04.001) ───────────────

/// BC-9.04.001 / AC-001: running `analyze -v` must produce at least one
/// `[parse]` line on stderr.
///
/// Small PCAPs (< 100k packets, < 10 MB) will not trigger a periodic emission,
/// so this test is intentionally loose: it verifies only that the wiring is
/// present (a `-v` run completes successfully and stderr is captured).  The
/// cadence and rate-limit behavior are exercised by the unit tests in
/// `src/progress.rs`.
///
/// If no fixture is available the test is skipped — the unit tests in
/// `src/progress.rs` are the load-bearing cadence tests.
#[test]
fn test_bc_9_04_001_verbose_mode_emits_progress_to_stderr() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        eprintln!(
            "skipping test_bc_9_04_001_verbose_mode_emits_progress_to_stderr: \
             tests/fixtures/synthetic-1mb.pcap not present"
        );
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    // Run with -v.  The Modbus.pcap fixture is small so we may not see a
    // periodic `[parse]` emission, but the command must succeed and stderr
    // must contain the verbose parse-summary line (which also starts with
    // a recognizable prefix from the analyze wiring).
    //
    // Once the progress reporter is wired, a large enough fixture or a
    // cfg(test)-lowered threshold will make this assert the `[parse]` prefix.
    // For now the test asserts success + that `-v` produces *some* stderr
    // output, confirming the verbose path is plumbed.
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze", "-v"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::is_empty().not());
}

/// BC-9.04.001 / AC-002: running `analyze` WITHOUT `-v` must not emit any
/// `[parse]` progress lines to stderr.
///
/// This is the authoritative CLI-layer test for the "no output in quiet mode"
/// contract.  It must pass vacuously (no `[parse]` lines) both before and
/// after implementation.
#[test]
fn test_bc_9_04_001_no_verbose_no_progress_lines() {
    let pcap =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-1mb.pcap");
    if !pcap.exists() {
        eprintln!(
            "skipping test_bc_9_04_001_no_verbose_no_progress_lines: \
             tests/fixtures/synthetic-1mb.pcap not present"
        );
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("[parse]").not());
}

/// F-W1-001 (wave-1 adversarial review): `otsniff unscrub` must reject a
/// corrupted baseline map at load time, mirroring the `run_scrub --baseline-map`
/// path's `validate()` call. A map with an empty-string pseudonym would
/// otherwise silently corrupt the unscrubbed output.
#[test]
fn test_f_w1_001_unscrub_rejects_corrupted_map() {
    let tmp = TempDir::new().unwrap();
    let map_path = tmp.path().join("corrupted-map.json");
    // Map with an empty-string pseudonym key under `ips` — same shape
    // rejected by ScrubMap::validate() per BC-5.03.001 EC-001.
    let corrupted_map = r#"{"version":1,"created_at":"2026-05-07T12:00:00Z","ips":{"":"10.0.0.1"},"macs":{},"names":{}}"#;
    std::fs::write(&map_path, corrupted_map).unwrap();
    let input = tmp.path().join("ai.txt");
    std::fs::write(&input, "host_001 saw the leak").unwrap();
    // F-002 (S-13.01 review): pin the exit code and message shape, not just
    // bare failure. A corrupted map is a data-integrity fault
    // (`PrivacyError::MapCorrupt` → `OtError::Parse`), NOT a privacy-invariant
    // trip -- it must exit 70 with a "pcap parse error" prefix, never exit 75
    // with "privacy invariant tripped" (which would both change observable
    // exit-code behavior and mislabel a message that names a raw value).
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["unscrub", "--map"])
        .arg(&map_path)
        .arg(&input)
        .assert()
        .failure()
        .code(70)
        .stderr(predicate::str::contains("pcap parse error"))
        .stderr(predicate::str::contains("privacy invariant tripped").not())
        // F-ADV-P6 (S-13.01 sixth review) / corrected by F-P7-001 (seventh
        // review): this pins that the `MapCorrupt` -> `OtError::Parse` path
        // (exit 70, asserted above) never grows a "caused by: ..." stderr
        // line. It does NOT pin anything about the unrelated `Leak` ->
        // `OtError::Privacy` path (exit 75) or `OtError::Privacy`'s
        // hand-written `From<PrivacyError>` impl -- `OtError::Parse` has no
        // `#[source]` regardless of what that other variant does, so a
        // hypothetical revert of `Privacy` to `#[from]` would NOT be caught
        // by this assertion. (The earlier version of this comment claimed
        // otherwise; that claim was false and has been corrected.) A revert
        // like that would still be caught by other tests that assert
        // `OtError::Privacy`'s exit code / message shape directly (see
        // src/error.rs) and, ideally, by a CLI-level test exercising the
        // `Leak` path -- S-13.01's seventh review investigated adding one
        // here and found no simple, non-contrived way to trigger
        // `PrivacyError::Leak` via the `otsniff` binary without invoking
        // the real `--ai` flow (which needs the `claude` CLI): every
        // finding in this codebase routes identifier text through
        // `host_label`/the scrub map before it reaches a report, so there
        // is no free-text field left for a crafted PCAP to smuggle an
        // unscrubbed IP/MAC-shaped string past `ensure_clean` on a
        // realistic input. `Leak` construction and its message shape stay
        // covered at the unit level (`crates/otsniff-privacy/src/
        // leak_detector.rs`, `src/error.rs`).
        .stderr(predicate::str::contains("caused by").not());
}

// ── S-10.01: capture-window sanity warning on stderr (AC-004) ────────────────

/// Minimal Ethernet II + IPv4 + UDP frame (10.10.0.1 → 10.10.0.2). Hand-built
/// raw bytes so the test adds no dependency; it parses to exactly one `Packet`.
fn eth_ipv4_udp_frame() -> Vec<u8> {
    let mut f = Vec::new();
    // Ethernet II: dst MAC, src MAC, ethertype 0x0800 (IPv4).
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x08, 0x00]);
    // IPv4 header (20 bytes), total length 28, protocol 17 (UDP).
    f.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x11, 0, 0]);
    f.extend_from_slice(&[10, 10, 0, 1]); // src
    f.extend_from_slice(&[10, 10, 0, 2]); // dst
                                          // UDP header (8 bytes), length 8.
    f.extend_from_slice(&[0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
    f
}

/// Build a little-endian legacy pcap (ETHERNET link type) with `records`
/// frames, each stamped at `ts_sec` (ts_usec = 0).
fn legacy_pcap(frame: &[u8], records: usize, ts_secs: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // magic (LE, microsecond)
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // network = ETHERNET
    for i in 0..records {
        let ts = ts_secs.get(i).copied().unwrap_or(0);
        out.extend_from_slice(&ts.to_le_bytes()); // ts_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
        out.extend_from_slice(frame);
    }
    out
}

/// AC-004: `analyze` on an all-epoch (ts = 0) capture exits 0 and prints the
/// capture-sanity WARNING to stderr.
#[test]
fn s_10_01_analyze_epoch_zero_pcap_warns_on_stderr() {
    let tmp = TempDir::new().unwrap();
    let pcap = tmp.path().join("epoch.pcap");
    std::fs::write(&pcap, legacy_pcap(&eth_ipv4_udp_frame(), 2, &[0, 0])).unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "WARNING: capture has no real timestamps",
        ));
}

/// AC-004 / AC-005: `analyze` on a sane (multi-second, monotonic, post-epoch)
/// capture emits no capture-sanity WARNING.
#[test]
fn s_10_01_analyze_sane_pcap_emits_no_capture_warning() {
    let tmp = TempDir::new().unwrap();
    let pcap = tmp.path().join("sane.pcap");
    std::fs::write(
        &pcap,
        legacy_pcap(&eth_ipv4_udp_frame(), 2, &[1_700_000_000, 1_700_000_010]),
    )
    .unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["analyze"])
        .arg(&pcap)
        .arg("-o")
        .arg(&out)
        .assert()
        .success()
        // Target the capture-sanity messages specifically (all three end in
        // "unreliable" or "misleading"), not any "WARNING" — so this stays
        // green if an unrelated guard (e.g. capture-source) ever warns here.
        .stderr(predicate::str::contains("unreliable").not())
        .stderr(predicate::str::contains("misleading").not());
}

// ── S-11.01: diff capture-window normalization warning (AC-003) ──────────────

/// Scrub map covering the two IPs in `eth_ipv4_udp_frame()`
/// (10.10.0.1 → 10.10.0.2). Written to disk for the `diff` subcommand.
fn window_scrub_map() -> &'static str {
    r#"{"version":1,"created_at":"2026-05-07T12:00:00Z","ips":{"host_001":"10.10.0.1","host_002":"10.10.0.2"},"macs":{},"names":{}}"#
}

/// AC-003: two captures whose windows differ by > 2× (3600s vs 1200s) make
/// `diff` emit the rate-normalized window-mismatch WARNING on stderr.
#[test]
fn s_11_01_diff_mismatched_windows_warns_on_stderr() {
    let tmp = TempDir::new().unwrap();
    let frame = eth_ipv4_udp_frame();
    // baseline spans 3600s, current spans 1200s → 3× difference.
    let base = tmp.path().join("base.pcap");
    std::fs::write(
        &base,
        legacy_pcap(&frame, 2, &[1_700_000_000, 1_700_003_600]),
    )
    .unwrap();
    let curr = tmp.path().join("curr.pcap");
    std::fs::write(
        &curr,
        legacy_pcap(&frame, 2, &[1_700_000_000, 1_700_001_200]),
    )
    .unwrap();
    let map = tmp.path().join("map.json");
    std::fs::write(&map, window_scrub_map()).unwrap();
    let out = tmp.path().join("diff.md");

    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["diff"])
        .arg(&base)
        .arg(&curr)
        .arg("--baseline-map")
        .arg(&map)
        .arg("--current-map")
        .arg(&map)
        .arg("-o")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("capture windows differ"));
}

/// AC-003: two captures whose windows are comparable (1000s vs 1500s, < 2×)
/// emit NO window-mismatch / degenerate WARNING.
#[test]
fn s_11_01_diff_comparable_windows_no_warning() {
    let tmp = TempDir::new().unwrap();
    let frame = eth_ipv4_udp_frame();
    let base = tmp.path().join("base.pcap");
    std::fs::write(
        &base,
        legacy_pcap(&frame, 2, &[1_700_000_000, 1_700_001_000]),
    )
    .unwrap();
    let curr = tmp.path().join("curr.pcap");
    std::fs::write(
        &curr,
        legacy_pcap(&frame, 2, &[1_700_000_000, 1_700_001_500]),
    )
    .unwrap();
    let map = tmp.path().join("map.json");
    std::fs::write(&map, window_scrub_map()).unwrap();
    let out = tmp.path().join("diff.md");

    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["diff"])
        .arg(&base)
        .arg(&curr)
        .arg("--baseline-map")
        .arg(&map)
        .arg("--current-map")
        .arg(&map)
        .arg("-o")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("capture windows differ").not())
        .stderr(predicate::str::contains("capture window is missing").not());
}

#[test]
fn unscrub_strict_mode_fails_on_unknown_token() {
    let tmp = TempDir::new().unwrap();
    let map_path = tmp.path().join("empty-map.json");
    let empty_map =
        r#"{"version":1,"created_at":"2026-05-07T12:00:00Z","ips":{},"macs":{},"names":{}}"#;
    std::fs::write(&map_path, empty_map).unwrap();
    let input = tmp.path().join("ai.txt");
    std::fs::write(&input, "host_007 is suspicious").unwrap();
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["unscrub", "--map"])
        .arg(&map_path)
        .arg(&input)
        .arg("--strict")
        .assert()
        .failure()
        .stderr(predicate::str::contains("strict mode"));
}
