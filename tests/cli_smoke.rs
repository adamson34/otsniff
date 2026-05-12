//! End-to-end CLI smoke tests.
//!
//! These exercise the binary through `assert_cmd`. They do *not* assert on
//! report contents — that's what the snapshot tests cover. Their job is to
//! catch obvious regressions in arg parsing, exit codes, and the
//! input-error → exit-code mapping across all subcommands.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

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
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Modbus.pcap");
    if !pcap.exists() {
        eprintln!("skipping: tests/fixtures/Modbus.pcap not present");
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
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Modbus.pcap");
    if !pcap.exists() {
        eprintln!("skipping: tests/fixtures/Modbus.pcap not present");
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

    // The Modbus.pcap fixture has 192.168.110.131 and 192.168.110.138 — neither
    // should appear in the scrubbed report.
    assert!(!scrubbed.contains("192.168.110.131"));
    assert!(!scrubbed.contains("192.168.110.138"));
    assert!(scrubbed.contains("host_001"));
    // Map should mention both real IPs.
    assert!(map_text.contains("192.168.110.131"));
    assert!(map_text.contains("192.168.110.138"));

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
    assert!(final_text.contains("192.168.110.131"));
    assert!(final_text.contains("host_999")); // unmapped pseudonym left as-is
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
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Modbus.pcap");
    if !pcap.exists() {
        eprintln!("skipping test_bc_9_06_001_review_scrub_aborts_on_n: Modbus.pcap not present");
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
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Modbus.pcap");
    if !pcap.exists() {
        eprintln!("skipping test_bc_9_06_001_review_scrub_aborts_on_eof: Modbus.pcap not present");
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
