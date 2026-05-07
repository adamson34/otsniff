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
        .stdout(predicate::str::contains("report"))
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
fn report_help_describes_command() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["report", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("HTML report"))
        .stdout(predicate::str::contains("--ot-subnet"));
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
fn report_nonexistent_input_exits_2() {
    let tmp = TempDir::new().unwrap();
    let bogus = tmp.path().join("does-not-exist.pcap");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["report"])
        .arg(&bogus)
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("could not open input"));
}

#[test]
fn report_malformed_input_exits_2() {
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("garbage.pcap");
    std::fs::write(&bad, b"this is not a pcap file at all").unwrap();
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["report"])
        .arg(&bad)
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a valid pcap"));
}

#[test]
fn report_valid_pcap_produces_html_and_exits_0() {
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Modbus.pcap");
    if !pcap.exists() {
        eprintln!("skipping: tests/fixtures/Modbus.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["report"])
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

#[test]
fn unscrub_strict_mode_fails_on_unknown_token() {
    let tmp = TempDir::new().unwrap();
    let map_path = tmp.path().join("empty-map.json");
    let empty_map = r#"{"version":1,"created_at":"2026-05-07T12:00:00Z","ips":{},"macs":{}}"#;
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
