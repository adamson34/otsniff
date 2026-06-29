//! End-to-end CLI coverage for `otsniff analyze --policy` (ADR-0013 step 6a):
//! a real PCAP + a Zonewarden policy must produce a report containing the
//! "Zonewarden — Segmentation Conformance" section.

use assert_cmd::Command;

/// The one committed PCAP fixture (per the .gitignore exception — the other
/// captures are gitignored and absent in CI). Absolute via CARGO_MANIFEST_DIR so
/// it resolves regardless of the test process's cwd.
const PCAP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/synthetic-1mb.pcap"
);

#[test]
fn analyze_with_policy_emits_conformance_section() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "zones:\n  - id: ot\n    name: OT\n    purdue_level: L2\n    members: [\"192.168.0.0/16\"]\n  - id: it\n    name: IT\n    purdue_level: L4\n    members: [\"10.0.0.0/8\"]\nconduits: []\n",
    )
    .unwrap();
    let out = dir.path().join("report.html");

    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("analyze")
        .arg(PCAP)
        .arg("--policy")
        .arg(&policy)
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    let html = std::fs::read_to_string(&out).unwrap();
    assert!(
        html.contains("Zonewarden — Segmentation Conformance"),
        "report should carry the conformance section when --policy is given"
    );
    assert!(
        html.contains("Policy digest:"),
        "report should carry the deterministic policy digest"
    );
}

#[test]
fn analyze_without_policy_has_no_conformance_section() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("report.html");
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("analyze")
        .arg(PCAP)
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(
        !html.contains("Zonewarden — Segmentation Conformance"),
        "no conformance section without --policy"
    );
}
