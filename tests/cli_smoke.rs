//! End-to-end CLI smoke tests.
//!
//! These exercise the binary through `assert_cmd`. They do *not* assert on
//! report contents — that's what the snapshot tests cover. Their job is to
//! catch obvious regressions in arg parsing, exit codes, and the
//! input-error → exit-code mapping.

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
        .stdout(predicate::str::contains("PCAP triage"))
        .stdout(predicate::str::contains("--ot-subnet"));
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
fn missing_input_arg_exits_with_clap_error() {
    // clap's missing-required-arg path; exits 2 by clap convention.
    Command::cargo_bin("otsniff")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn nonexistent_input_exits_2() {
    let tmp = TempDir::new().unwrap();
    let bogus = tmp.path().join("does-not-exist.pcap");
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg(&bogus)
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("could not open input"));
}

#[test]
fn malformed_input_exits_2() {
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("garbage.pcap");
    std::fs::write(&bad, b"this is not a pcap file at all").unwrap();
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg(&bad)
        .arg("-o")
        .arg(tmp.path().join("out.html"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a valid pcap"));
}

#[test]
fn valid_pcap_produces_html_and_exits_0() {
    let pcap = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Modbus.pcap");
    if !pcap.exists() {
        eprintln!("skipping: tests/fixtures/Modbus.pcap not present");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
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
fn ot_subnet_flag_parses_cidr() {
    let tmp = TempDir::new().unwrap();
    let bogus = tmp.path().join("does-not-exist.pcap");
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("--ot-subnet")
        .arg("not-a-cidr")
        .arg(&bogus)
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value").or(predicate::str::contains("error")));
}
