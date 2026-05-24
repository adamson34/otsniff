//! Acceptance tests for S-6.02: `otsniff diff` subcommand + delta computation.
//!
//! Covers BC-9.05.001 (subcommand CLI surface) and BC-3.08.001..003 (diff
//! semantics: host deltas, finding deltas, role/flow shifts).
//!
//! ALL tests in this file are expected to FAIL until the implementer completes
//! S-6.02 step 4 (`diff::compute`).  The `compute` stub panics with `todo!()`.
//!
//! TDD mode: strict.  Tests assert behavioral contracts of `crate::diff::compute`
//! and the CLI `diff` subcommand.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use assert_cmd::Command;
use chrono::Utc;
use predicates::prelude::*;

use otsniff::diff::{compute, DiffInput, DEFAULT_FLOW_SHIFT_MULTIPLIER};
use otsniff::findings::{Finding, Severity};
use otsniff::observe::{FlowKey, FlowObs, HostObs, Observations};
use otsniff::scrub::ScrubMap;

// ---------------------------------------------------------------------------
// Test-only fixture helpers
// ---------------------------------------------------------------------------

/// Build a minimal `HostObs` suitable for insertion into `Observations.hosts`.
fn host_obs(ip: IpAddr, protocols: &[&str]) -> HostObs {
    let now = Utc::now();
    HostObs {
        ip,
        macs: vec![],
        protocols: protocols.iter().map(|s| s.to_string()).collect(),
        first_seen: now,
        last_seen: now,
        packets: 1,
        bytes: 100,
        in_ot_zone: false,
    }
}

/// Build a minimal `ScrubMap` containing a single IP pseudonym.
/// `pseudonym` is the key (e.g. "host_001"), `real_ip` is the value.
fn scrub_map_with_ips(entries: &[(&str, &str)]) -> ScrubMap {
    let now = Utc::now();
    ScrubMap {
        version: 1,
        created_at: now,
        ips: entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        macs: BTreeMap::new(),
        names: BTreeMap::new(),
    }
}

/// Build a `Finding` with the given rule_id and addresses/port baked into the
/// title so the tuple-matching logic in `compute` can distinguish them.
fn make_finding(
    rule_id: &'static str,
    src_pseudo: &str,
    dst_pseudo: &str,
    dst_port: u16,
) -> Finding {
    Finding {
        id: rule_id,
        severity: Severity::Medium,
        title: format!("{rule_id}: {src_pseudo} → {dst_pseudo}:{dst_port}"),
        summary: format!("test finding {src_pseudo} → {dst_pseudo}:{dst_port}"),
        evidence: vec![format!("src={src_pseudo} dst={dst_pseudo} port={dst_port}")],
        recommendation: "investigate",
        playbook: vec![],
    }
}

/// Build a minimal `FlowObs` for `Observations.flows`.
/// Key is `"src->dst:port/proto"` (not load-bearing for compute, just needs to
/// be present so the observer sees a flow with the given bytes).
fn flow_obs(src: IpAddr, dst: IpAddr, dst_port: u16, proto: u8, bytes: u64) -> (String, FlowObs) {
    let now = Utc::now();
    let key = FlowKey {
        src,
        dst,
        dst_port,
        proto,
    };
    let key_str = format!("{}->{}:{}/{}", src, dst, dst_port, proto);
    let obs = FlowObs {
        key,
        packets: 1,
        bytes,
        first_seen: now,
        last_seen: now,
        label: None,
        unique_src_ports: HashSet::new(),
    };
    (key_str, obs)
}

// ---------------------------------------------------------------------------
// AC-001 (BC-9.05.001) — CLI subcommand surface
// ---------------------------------------------------------------------------

/// AC-001 | BC-9.05.001
/// `otsniff --help` must list the `diff` subcommand.
#[test]
fn test_ac_001_diff_subcommand_in_help() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("diff"));
}

/// AC-001 | BC-9.05.001
/// `otsniff diff --help` must document all five required arguments:
///   <BASELINE_PCAP>, <CURRENT_PCAP>, --baseline-map, --current-map, -o/--output
/// and the optional --flow-shift-multiplier flag.
#[test]
fn test_ac_001_diff_subcommand_help_documents_args() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .args(["diff", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("baseline-pcap").or(predicate::str::contains("BASELINE_PCAP")),
        )
        .stdout(
            predicate::str::contains("current-pcap").or(predicate::str::contains("CURRENT_PCAP")),
        )
        .stdout(predicate::str::contains("--baseline-map"))
        .stdout(predicate::str::contains("--current-map"))
        .stdout(predicate::str::contains("--output").or(predicate::str::contains("-o")))
        .stdout(predicate::str::contains("flow-shift-multiplier"));
}

/// AC-001 | BC-9.05.001
/// Invoking `otsniff diff` with no arguments must exit non-zero and print a
/// usage / required-argument message to stderr.
#[test]
fn test_ac_001_diff_missing_args_fails_with_usage() {
    Command::cargo_bin("otsniff")
        .unwrap()
        .arg("diff")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("required")
                .or(predicate::str::contains("Usage"))
                .or(predicate::str::contains("usage")),
        );
}

// ---------------------------------------------------------------------------
// AC-002 (BC-3.08.001) — hosts_new + hosts_gone
// ---------------------------------------------------------------------------

/// AC-002 | BC-3.08.001
/// Baseline has hosts A (1.0.0.1) and B (1.0.0.2); current has B and C (1.0.0.3).
/// Expect: hosts_new == [C], hosts_gone == [A].
#[test]
fn test_ac_002_host_added_appears_in_hosts_new() {
    let ip_a: IpAddr = "1.0.0.1".parse().unwrap();
    let ip_b: IpAddr = "1.0.0.2".parse().unwrap();
    let ip_c: IpAddr = "1.0.0.3".parse().unwrap();

    // Baseline observations: hosts A + B
    let mut base_obs = Observations::default();
    base_obs.hosts.insert(ip_a, host_obs(ip_a, &[]));
    base_obs.hosts.insert(ip_b, host_obs(ip_b, &[]));
    // Map: host_001 → A, host_002 → B
    let base_map = scrub_map_with_ips(&[("host_001", "1.0.0.1"), ("host_002", "1.0.0.2")]);

    // Current observations: hosts B + C
    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip_b, host_obs(ip_b, &[]));
    curr_obs.hosts.insert(ip_c, host_obs(ip_c, &[]));
    // Map: host_002 → B (reused), host_003 → C
    let curr_map = scrub_map_with_ips(&[("host_002", "1.0.0.2"), ("host_003", "1.0.0.3")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    // hosts_new should contain exactly C (pseudonym "host_003").
    // F-W2-003: assert by pseudonym, not raw IP — the Diff output is
    // pseudonymized.
    assert_eq!(
        diff.hosts_new.len(),
        1,
        "BC-3.08.001 AC-002: expected 1 new host (C / host_003), got {:?}",
        diff.hosts_new
            .iter()
            .map(|h| h.pseudonym.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        diff.hosts_new[0].pseudonym, "host_003",
        "BC-3.08.001 AC-002: hosts_new[0] should be host_003"
    );
    let _ = ip_c; // kept for fixture parity even though we now assert on pseudonym

    // hosts_gone should contain exactly A (pseudonym "host_001").
    assert_eq!(
        diff.hosts_gone.len(),
        1,
        "BC-3.08.001 AC-002: expected 1 gone host (A / host_001), got {:?}",
        diff.hosts_gone
            .iter()
            .map(|h| h.pseudonym.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        diff.hosts_gone[0].pseudonym, "host_001",
        "BC-3.08.001 AC-002: hosts_gone[0] should be host_001"
    );
    let _ = ip_a;
}

/// AC-002 | BC-3.08.001
/// The same real IP appearing under DIFFERENT pseudonyms in baseline vs. current
/// must be treated as two different hosts, because identification uses pseudonyms.
/// This is the load-bearing test for the "identified by pseudonym, not raw IP" rule.
#[test]
fn test_ac_002_identification_by_pseudonym_not_ip() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Baseline: real IP 10.0.0.1 mapped to host_001
    let mut base_obs = Observations::default();
    base_obs.hosts.insert(ip, host_obs(ip, &[]));
    let base_map = scrub_map_with_ips(&[("host_001", "10.0.0.1")]);

    // Current: same real IP 10.0.0.1 but mapped to host_099 (different pseudonym)
    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip, host_obs(ip, &[]));
    let curr_map = scrub_map_with_ips(&[("host_099", "10.0.0.1")]);

    // host_001 ≠ host_099 → host_001 is "gone", host_099 is "new"
    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert_eq!(
        diff.hosts_new.len(),
        1,
        "BC-3.08.001 AC-002 (pseudonym identification): host_099 should be new"
    );
    assert_eq!(
        diff.hosts_gone.len(),
        1,
        "BC-3.08.001 AC-002 (pseudonym identification): host_001 should be gone"
    );
}

/// AC-002 | BC-3.08.001 EC-001
/// When no hosts are shared between baseline and current, every current host is
/// in hosts_new and every baseline host is in hosts_gone.
#[test]
fn test_ac_002_empty_intersection_is_all_new_and_all_gone() {
    let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let ip_b: IpAddr = "192.168.1.2".parse().unwrap();
    let ip_c: IpAddr = "10.10.0.1".parse().unwrap();
    let ip_d: IpAddr = "10.10.0.2".parse().unwrap();

    let mut base_obs = Observations::default();
    base_obs.hosts.insert(ip_a, host_obs(ip_a, &[]));
    base_obs.hosts.insert(ip_b, host_obs(ip_b, &[]));
    let base_map = scrub_map_with_ips(&[("host_001", "192.168.1.1"), ("host_002", "192.168.1.2")]);

    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip_c, host_obs(ip_c, &[]));
    curr_obs.hosts.insert(ip_d, host_obs(ip_d, &[]));
    // Pseudonyms that share no overlap with baseline
    let curr_map = scrub_map_with_ips(&[("host_003", "10.10.0.1"), ("host_004", "10.10.0.2")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert_eq!(
        diff.hosts_new.len(),
        2,
        "BC-3.08.001 EC-001: all current hosts ({}) should be new",
        2
    );
    assert_eq!(
        diff.hosts_gone.len(),
        2,
        "BC-3.08.001 EC-001: all baseline hosts ({}) should be gone",
        2
    );
}

// ---------------------------------------------------------------------------
// AC-003 (BC-3.08.002) — finding deltas
// ---------------------------------------------------------------------------

/// AC-003 | BC-3.08.002
/// A finding present only in current must appear in `findings_new`.
#[test]
fn test_ac_003_finding_new_in_current_only_is_in_findings_new() {
    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[]);
    let curr_obs = Observations::default();
    let curr_map = scrub_map_with_ips(&[]);

    let base_findings: Vec<Finding> = vec![];
    let curr_findings = vec![make_finding("R-001", "host_001", "host_002", 502)];

    // The implementer must extend DiffInput or compute's signature to accept
    // pre-computed findings.  The test here documents the required behaviour:
    // call compute with the findings attached to DiffInput.
    // (If DiffInput doesn't yet carry findings, this will fail to compile
    // until the implementer adds the field — that is intentional Red Gate
    // behaviour for AC-003.)
    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &base_findings,
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &curr_findings,
        },
    );

    assert_eq!(
        diff.findings_new.len(),
        1,
        "BC-3.08.002 AC-003: finding only in current must appear in findings_new"
    );
    assert!(
        diff.findings_recurring.is_empty(),
        "BC-3.08.002 AC-003: findings_recurring must be empty"
    );
    assert!(
        diff.findings_resolved.is_empty(),
        "BC-3.08.002 AC-003: findings_resolved must be empty"
    );
}

/// AC-003 | BC-3.08.002
/// A finding present in both baseline and current must appear in
/// `findings_recurring`.
#[test]
fn test_ac_003_finding_in_both_is_findings_recurring() {
    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[]);
    let curr_obs = Observations::default();
    let curr_map = scrub_map_with_ips(&[]);

    // Same tuple in both
    let base_findings = vec![make_finding("R-001", "host_001", "host_002", 502)];
    let curr_findings = vec![make_finding("R-001", "host_001", "host_002", 502)];

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &base_findings,
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &curr_findings,
        },
    );

    assert_eq!(
        diff.findings_recurring.len(),
        1,
        "BC-3.08.002 AC-003: finding in both must appear in findings_recurring"
    );
    assert!(
        diff.findings_new.is_empty(),
        "BC-3.08.002 AC-003: findings_new must be empty when finding is recurring"
    );
    assert!(
        diff.findings_resolved.is_empty(),
        "BC-3.08.002 AC-003: findings_resolved must be empty when finding is recurring"
    );
}

/// AC-003 | BC-3.08.002
/// A finding present only in baseline must appear in `findings_resolved`.
#[test]
fn test_ac_003_finding_only_in_baseline_is_findings_resolved() {
    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[]);
    let curr_obs = Observations::default();
    let curr_map = scrub_map_with_ips(&[]);

    let base_findings = vec![make_finding("R-001", "host_001", "host_002", 502)];
    let curr_findings: Vec<Finding> = vec![];

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &base_findings,
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &curr_findings,
        },
    );

    assert_eq!(
        diff.findings_resolved.len(),
        1,
        "BC-3.08.002 AC-003: finding only in baseline must appear in findings_resolved"
    );
    assert!(
        diff.findings_new.is_empty(),
        "BC-3.08.002 AC-003: findings_new must be empty"
    );
    assert!(
        diff.findings_recurring.is_empty(),
        "BC-3.08.002 AC-003: findings_recurring must be empty"
    );
}

/// AC-003 | BC-3.08.002
/// Matching is by exact (rule_id, src, dst, dst_port) tuple.
/// Baseline: (R-001, host_001, host_002, 502).
/// Current:  (R-001, host_001, host_002, 503) — different port.
/// Expect: 1 findings_new, 1 findings_resolved, 0 findings_recurring.
#[test]
fn test_ac_003_matching_by_exact_tuple_no_near_matches() {
    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[]);
    let curr_obs = Observations::default();
    let curr_map = scrub_map_with_ips(&[]);

    let base_findings = vec![make_finding("R-001", "host_001", "host_002", 502)];
    let curr_findings = vec![make_finding("R-001", "host_001", "host_002", 503)];

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &base_findings,
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &curr_findings,
        },
    );

    assert_eq!(
        diff.findings_new.len(),
        1,
        "BC-3.08.002 AC-003 (no near-match): different dst_port must not join"
    );
    assert_eq!(
        diff.findings_resolved.len(),
        1,
        "BC-3.08.002 AC-003 (no near-match): baseline finding must be resolved"
    );
    assert_eq!(
        diff.findings_recurring.len(),
        0,
        "BC-3.08.002 AC-003 (no near-match): findings_recurring must be empty"
    );
}

// ---------------------------------------------------------------------------
// AC-004 (BC-3.08.003) — role shifts + flow shifts
// ---------------------------------------------------------------------------

/// AC-004 | BC-3.08.003
/// A host whose inferred role changed from ItEndpoint (baseline) to Plc (current)
/// must appear in `role_shifts`.
#[test]
fn test_ac_004_role_shift_detected() {
    let ip: IpAddr = "172.16.0.10".parse().unwrap();

    let mut base_obs = Observations::default();
    base_obs.hosts.insert(ip, host_obs(ip, &["smb"])); // → ItEndpoint
    let base_map = scrub_map_with_ips(&[("host_001", "172.16.0.10")]);

    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip, host_obs(ip, &["enip"])); // → Plc
    let curr_map = scrub_map_with_ips(&[("host_001", "172.16.0.10")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert_eq!(
        diff.role_shifts.len(),
        1,
        "BC-3.08.003 AC-004: expected 1 role shift for host_001"
    );
    let rs = &diff.role_shifts[0];
    assert_eq!(
        rs.pseudonym, "host_001",
        "BC-3.08.003 AC-004: role_shifts[0].pseudonym should be host_001"
    );
    // Old role should be "IT endpoint" or equivalent label
    assert!(
        rs.old_role.to_lowercase().contains("it")
            || rs.old_role.to_lowercase().contains("endpoint"),
        "BC-3.08.003 AC-004: old_role should describe IT endpoint, got '{}'",
        rs.old_role
    );
    // New role should be "PLC" or equivalent label
    assert!(
        rs.new_role.to_lowercase().contains("plc")
            || rs.new_role.to_lowercase().contains("controller"),
        "BC-3.08.003 AC-004: new_role should describe PLC/controller, got '{}'",
        rs.new_role
    );
}

/// AC-004 | BC-3.08.003
/// A host with the same role in both captures must NOT appear in `role_shifts`.
#[test]
fn test_ac_004_no_role_shift_when_role_unchanged() {
    let ip: IpAddr = "172.16.0.11".parse().unwrap();

    let mut base_obs = Observations::default();
    base_obs.hosts.insert(ip, host_obs(ip, &["enip"])); // → Plc
    let base_map = scrub_map_with_ips(&[("host_001", "172.16.0.11")]);

    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip, host_obs(ip, &["enip"])); // → Plc (unchanged)
    let curr_map = scrub_map_with_ips(&[("host_001", "172.16.0.11")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert!(
        diff.role_shifts.is_empty(),
        "BC-3.08.003 AC-004: role_shifts must be empty when role is unchanged"
    );
}

/// AC-004 | BC-3.08.003
/// A flow that exists only in the current capture should appear in `flow_shifts`
/// with `baseline_bytes: None` and `current_bytes: Some(...)`.
#[test]
fn test_ac_004_new_flow_pair_appears_in_flow_shifts() {
    let src: IpAddr = "10.0.0.1".parse().unwrap();
    let dst: IpAddr = "10.0.0.2".parse().unwrap();

    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")]);

    let mut curr_obs = Observations::default();
    let (fk, fv) = flow_obs(src, dst, 502, 6, 1024);
    curr_obs.flows.insert(fk, fv);
    let curr_map = scrub_map_with_ips(&[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    // F-W2-002: a flow that exists only in `current` is no longer in
    // `flow_shifts` — it goes into `flows_new`. `flow_shifts` is reserved
    // for two-sided volume shifts.
    assert!(
        diff.flow_shifts.is_empty(),
        "F-W2-002: a current-only flow must NOT appear in flow_shifts \
         (which is now reserved for two-sided volume shifts); got {} entries",
        diff.flow_shifts.len()
    );
    assert_eq!(
        diff.flows_new.len(),
        1,
        "F-W2-002: a current-only flow should appear in flows_new"
    );
    let fs = &diff.flows_new[0];
    assert_eq!(
        fs.dst_port, 502,
        "BC-3.08.003 AC-004: flows_new entry should have dst_port 502"
    );
}

/// AC-004 | BC-3.08.003
/// A flow that exists in both captures but current bytes is 3× baseline must
/// appear in `flow_shifts` (above the default 2× threshold).
#[test]
fn test_ac_004_flow_volume_doubled_triggers_shift() {
    let src: IpAddr = "10.1.0.1".parse().unwrap();
    let dst: IpAddr = "10.1.0.2".parse().unwrap();

    let mut base_obs = Observations::default();
    let (fk_b, fv_b) = flow_obs(src, dst, 502, 6, 100); // 100 bytes in baseline
    base_obs.flows.insert(fk_b, fv_b);
    let base_map = scrub_map_with_ips(&[("host_010", "10.1.0.1"), ("host_011", "10.1.0.2")]);

    let mut curr_obs = Observations::default();
    let (fk_c, fv_c) = flow_obs(src, dst, 502, 6, 300); // 3× baseline → above 2× threshold
    curr_obs.flows.insert(fk_c, fv_c);
    let curr_map = scrub_map_with_ips(&[("host_010", "10.1.0.1"), ("host_011", "10.1.0.2")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert!(
        !diff.flow_shifts.is_empty(),
        "BC-3.08.003 AC-004: 3× volume increase (> {}× threshold) should produce a flow_shift",
        DEFAULT_FLOW_SHIFT_MULTIPLIER
    );
    let fs = &diff.flow_shifts[0];
    assert_eq!(
        fs.baseline_bytes, 100,
        "BC-3.08.003 AC-004: baseline_bytes should be 100"
    );
    assert_eq!(
        fs.current_bytes, 300,
        "BC-3.08.003 AC-004: current_bytes should be 300"
    );
    assert!(
        (fs.ratio - 3.0).abs() < 1e-9,
        "BC-3.08.003 AC-004: ratio for 300/100 should be 3.0, got {}",
        fs.ratio
    );
}

/// AC-004 | BC-3.08.003
/// A flow that exists in both captures with current bytes 1.5× baseline (below
/// the 2× default threshold) must NOT appear in `flow_shifts`.
#[test]
fn test_ac_004_flow_volume_minor_change_not_in_shifts() {
    let src: IpAddr = "10.2.0.1".parse().unwrap();
    let dst: IpAddr = "10.2.0.2".parse().unwrap();

    let mut base_obs = Observations::default();
    let (fk_b, fv_b) = flow_obs(src, dst, 502, 6, 200); // 200 bytes baseline
    base_obs.flows.insert(fk_b, fv_b);
    let base_map = scrub_map_with_ips(&[("host_020", "10.2.0.1"), ("host_021", "10.2.0.2")]);

    let mut curr_obs = Observations::default();
    let (fk_c, fv_c) = flow_obs(src, dst, 502, 6, 300); // 1.5× — below 2× threshold
    curr_obs.flows.insert(fk_c, fv_c);
    let curr_map = scrub_map_with_ips(&[("host_020", "10.2.0.1"), ("host_021", "10.2.0.2")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert!(
        diff.flow_shifts.is_empty(),
        "BC-3.08.003 AC-004: 1.5× volume (below {}× threshold) must NOT produce a flow_shift",
        DEFAULT_FLOW_SHIFT_MULTIPLIER
    );
}

// ---------------------------------------------------------------------------
// EC-002 — maps with no shared pseudonyms
// ---------------------------------------------------------------------------

/// EC-002
/// When baseline_map and current_map share no pseudonyms, compute must return a
/// valid `Diff` (not panic, not error).  The result is treated as if the S-6.01
/// merge step was skipped: all current hosts are new, all baseline hosts are gone.
#[test]
fn test_ec_002_maps_with_no_shared_pseudonyms_warns_and_proceeds() {
    let ip_a: IpAddr = "10.99.0.1".parse().unwrap();
    let ip_b: IpAddr = "10.99.0.2".parse().unwrap();

    let mut base_obs = Observations::default();
    base_obs.hosts.insert(ip_a, host_obs(ip_a, &[]));
    let base_map = scrub_map_with_ips(&[("host_001", "10.99.0.1")]);

    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip_b, host_obs(ip_b, &[]));
    // Completely disjoint pseudonym namespace
    let curr_map = scrub_map_with_ips(&[("host_100", "10.99.0.2")]);

    // Must not panic
    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    // With no shared pseudonyms the result behaves like EC-001: all new + all gone
    assert_eq!(
        diff.hosts_new.len(),
        1,
        "EC-002: all current hosts should be in hosts_new when maps share no pseudonyms"
    );
    assert_eq!(
        diff.hosts_gone.len(),
        1,
        "EC-002: all baseline hosts should be in hosts_gone when maps share no pseudonyms"
    );
}

// ============================================================================
// F-W2-001..004 regression tests (filed after S-6.02 end-to-end review)
// ============================================================================

use otsniff::diff::HostRef;

/// F-W2-001: the `Diff` enum variant's clap doc-comment must NOT leak the
/// internal `AC-001 (BC-9.05.001): subcommand exists` traceability marker
/// into the user-facing `--help` output. This is checked at the binary
/// level — we already exercise `--help` in CLI smoke tests, but specifically
/// regress against the marker text never appearing in stdout.
#[test]
fn test_f_w2_001_help_does_not_leak_bc_markers() {
    use assert_cmd::Command;

    let output = Command::cargo_bin("otsniff")
        .unwrap()
        .args(["diff", "--help"])
        .output()
        .expect("otsniff binary should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("AC-001"),
        "F-W2-001 regression: `otsniff diff --help` must not show internal \
         traceability markers (found 'AC-001' in output): {stdout}"
    );
    assert!(
        !stdout.contains("BC-9.05.001"),
        "F-W2-001 regression: `otsniff diff --help` must not show internal \
         BC IDs (found 'BC-9.05.001' in output): {stdout}"
    );
}

/// F-W2-002: a flow that exists in only one capture appears in `flows_new`
/// (or `flows_gone`), NOT in `flow_shifts`. `flow_shifts` is reserved for
/// volume changes on flows present in BOTH captures.
#[test]
fn test_f_w2_002_disjoint_flow_does_not_pad_flow_shifts() {
    let src: IpAddr = "10.2.0.1".parse().unwrap();
    let dst: IpAddr = "10.2.0.2".parse().unwrap();

    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[("host_200", "10.2.0.1"), ("host_201", "10.2.0.2")]);

    let mut curr_obs = Observations::default();
    let (fk, fv) = flow_obs(src, dst, 443, 6, 9999);
    curr_obs.flows.insert(fk, fv);
    let curr_map = scrub_map_with_ips(&[("host_200", "10.2.0.1"), ("host_201", "10.2.0.2")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert!(
        diff.flow_shifts.is_empty(),
        "F-W2-002: a flow only in current must NOT pad flow_shifts; got {} entries",
        diff.flow_shifts.len()
    );
    assert_eq!(
        diff.flows_new.len(),
        1,
        "F-W2-002: a current-only flow must appear in flows_new"
    );
}

/// F-W2-002 (mirror): same property for `flows_gone`.
#[test]
fn test_f_w2_002_disjoint_flow_baseline_only_goes_to_flows_gone() {
    let src: IpAddr = "10.3.0.1".parse().unwrap();
    let dst: IpAddr = "10.3.0.2".parse().unwrap();

    let mut base_obs = Observations::default();
    let (fk, fv) = flow_obs(src, dst, 22, 6, 8888);
    base_obs.flows.insert(fk, fv);
    let base_map = scrub_map_with_ips(&[("host_300", "10.3.0.1"), ("host_301", "10.3.0.2")]);

    let curr_obs = Observations::default();
    let curr_map = scrub_map_with_ips(&[("host_300", "10.3.0.1"), ("host_301", "10.3.0.2")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert!(
        diff.flow_shifts.is_empty(),
        "F-W2-002: a flow only in baseline must NOT pad flow_shifts"
    );
    assert_eq!(
        diff.flows_gone.len(),
        1,
        "F-W2-002: a baseline-only flow must appear in flows_gone"
    );
}

/// F-W2-003: `HostRef` carries the pseudonym, never the real IP. The diff
/// output is pseudonym-safe — nothing real-identifier-shaped leaks through.
#[test]
fn test_f_w2_003_hosts_new_uses_pseudonym_not_real_ip() {
    let ip_a: IpAddr = "192.168.42.1".parse().unwrap();

    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[]);

    let mut curr_obs = Observations::default();
    curr_obs.hosts.insert(ip_a, host_obs(ip_a, &["modbus"]));
    let curr_map = scrub_map_with_ips(&[("host_042", "192.168.42.1")]);

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &[],
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &[],
        },
    );

    assert_eq!(diff.hosts_new.len(), 1, "expected one new host");
    let hr: &HostRef = &diff.hosts_new[0];
    assert_eq!(
        hr.pseudonym, "host_042",
        "F-W2-003: hosts_new must carry the pseudonym, not the raw IP"
    );

    // Serialize the diff and confirm the raw IP never appears.
    let json = serde_json::to_string(&diff).expect("Diff serializes");
    assert!(
        !json.contains("192.168.42.1"),
        "F-W2-003 regression: real IP 192.168.42.1 leaked into Diff JSON: {json}"
    );
}

/// F-W2-004: the finding-key extractor handles real evidence formats. A
/// creds.ftp finding emits evidence like `"192.168.88.49:21 (34 packet(s))"`;
/// the matcher must extract dst+port and resolve dst to its pseudonym.
///
/// Without F-W2-004, two findings of the same `rule_id` against DIFFERENT
/// destination hosts would collide on `(rule_id, "", "", 0)` and be reported
/// as `findings_recurring`. With F-W2-004, they extract to different
/// `(rule_id, "", dst_pseudo, port)` tuples and are reported correctly as
/// `findings_new` / `findings_resolved`.
#[test]
fn test_f_w2_004_finding_dst_port_extracted_from_real_evidence() {
    use otsniff::findings::{Finding, Severity};

    // Two creds.ftp findings against different servers. Same rule_id; the
    // previous extractor would say they recur.
    let f_baseline = Finding {
        id: "creds.ftp",
        severity: Severity::Critical,
        title: "Plaintext FTP".to_string(),
        summary: "ftp on baseline server".to_string(),
        evidence: vec!["192.168.88.49:21 (34 packet(s))".to_string()],
        recommendation: "rotate",
        playbook: vec![],
    };
    let f_current = Finding {
        id: "creds.ftp",
        severity: Severity::Critical,
        title: "Plaintext FTP".to_string(),
        summary: "ftp on a DIFFERENT server".to_string(),
        evidence: vec!["192.168.88.51:21 (12 packet(s))".to_string()],
        recommendation: "rotate",
        playbook: vec![],
    };

    let base_obs = Observations::default();
    let base_map =
        scrub_map_with_ips(&[("host_049", "192.168.88.49"), ("host_051", "192.168.88.51")]);
    let curr_obs = Observations::default();
    let curr_map = base_map.clone();

    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: std::slice::from_ref(&f_baseline),
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: std::slice::from_ref(&f_current),
        },
    );

    // F-W2-004: dst extraction works. Different destinations → different keys
    // → no recurrence.
    assert!(
        diff.findings_recurring.is_empty(),
        "F-W2-004: two findings against DIFFERENT destination hosts must not \
         match as recurring; got {} recurring",
        diff.findings_recurring.len()
    );
    assert_eq!(
        diff.findings_new.len(),
        1,
        "F-W2-004: current-only finding should be in findings_new"
    );
    assert_eq!(
        diff.findings_resolved.len(),
        1,
        "F-W2-004: baseline-only finding should be in findings_resolved"
    );
}

/// F-W2-004 (positive): same `rule_id` + same destination IP across captures
/// → recurring, AFTER the extractor resolves the IP to its pseudonym.
#[test]
fn test_f_w2_004_same_dst_across_captures_is_recurring() {
    use otsniff::findings::{Finding, Severity};

    let f_both_sides = || Finding {
        id: "creds.telnet",
        severity: Severity::Critical,
        title: "Telnet".to_string(),
        summary: "telnet observed".to_string(),
        evidence: vec!["192.168.10.5:23 (100 packet(s))".to_string()],
        recommendation: "replace",
        playbook: vec![],
    };
    let base_obs = Observations::default();
    let base_map = scrub_map_with_ips(&[("host_005", "192.168.10.5")]);
    let curr_obs = Observations::default();
    let curr_map = base_map.clone();

    let f_b = f_both_sides();
    let f_c = f_both_sides();
    let diff = compute(
        DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: std::slice::from_ref(&f_b),
        },
        DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: std::slice::from_ref(&f_c),
        },
    );

    assert_eq!(
        diff.findings_recurring.len(),
        1,
        "F-W2-004: same rule_id + same destination should be recurring"
    );
    assert!(
        diff.findings_new.is_empty() && diff.findings_resolved.is_empty(),
        "F-W2-004: recurring case should not produce findings_new/resolved"
    );
}
