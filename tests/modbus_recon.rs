//! Integration tests for the `ics.modbus_unit_id_sweep` detector (S-2.11).
//!
//! Covers:
//!   BC-3.03.006 — sweep detection thresholds (Medium ≥5, High ≥50)
//!   AC-002       — below-threshold must not fire
//!   AC-002       — distinct (src, dst) pairs emit separate findings
//!   AC-002       — evidence includes count and first 10 unit IDs

use std::collections::BTreeSet;
use std::net::IpAddr;

use otsniff::findings::Severity;
use otsniff::observe::{ModbusFlowSummary, Observations};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn obs_with_unit_ids(src: &str, dst: &str, ids: &[u8]) -> Observations {
    let mut obs = Observations::default();
    let mut unit_ids = BTreeSet::new();
    for &id in ids {
        unit_ids.insert(id);
    }
    obs.modbus_flow_summary
        .insert((ip(src), ip(dst)), ModbusFlowSummary { unit_ids });
    obs
}

// ---------------------------------------------------------------------------
// BC-3.03.006: below threshold must not fire
// ---------------------------------------------------------------------------

/// BC-3.03.006: 4 distinct unit IDs (below the Medium threshold of 5) must
/// not produce any finding. The stub returns empty-Vec so this test vacuously
/// passes before implementation — it is paired with the positive threshold
/// tests below which will fail at stub stage.
#[test]
fn test_bc_3_03_006_below_threshold_does_not_fire() {
    let obs = obs_with_unit_ids("10.0.0.1", "10.0.0.2", &[1, 2, 3, 4]);
    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert!(
        findings.is_empty(),
        "BC-3.03.006: 4 unit IDs (below threshold of 5) must not fire, got {} finding(s)",
        findings.len()
    );
}

// ---------------------------------------------------------------------------
// BC-3.03.006: Medium threshold — exactly 5 unit IDs
// ---------------------------------------------------------------------------

/// BC-3.03.006 (AC-002): exactly 5 distinct unit IDs must produce one finding
/// at severity Medium with rule_id `ics.modbus_unit_id_sweep`.
#[test]
fn test_bc_3_03_006_at_medium_threshold_fires_medium() {
    let obs = obs_with_unit_ids("10.0.0.1", "10.0.0.2", &[1, 2, 3, 4, 5]);
    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "BC-3.03.006: exactly 5 unit IDs must produce exactly one finding, got {}",
        findings.len()
    );
    assert_eq!(
        findings[0].id, "ics.modbus_unit_id_sweep",
        "BC-3.03.006: finding rule_id must be 'ics.modbus_unit_id_sweep', got '{}'",
        findings[0].id
    );
    assert_eq!(
        findings[0].severity,
        Severity::Medium,
        "BC-3.03.006: 5 unit IDs must fire at Medium severity"
    );
}

// ---------------------------------------------------------------------------
// BC-3.03.006: Medium severity persists well above threshold (but below High)
// ---------------------------------------------------------------------------

/// BC-3.03.006: 20 distinct unit IDs (above Medium threshold, below High at 50)
/// must fire at Medium severity.
#[test]
fn test_bc_3_03_006_well_above_medium_fires_medium() {
    let ids: Vec<u8> = (1..=20).collect();
    let obs = obs_with_unit_ids("10.0.0.1", "10.0.0.2", &ids);
    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "BC-3.03.006: 20 unit IDs must produce exactly one finding"
    );
    assert_eq!(
        findings[0].severity,
        Severity::Medium,
        "BC-3.03.006: 20 unit IDs (below High threshold) must fire at Medium"
    );
}

// ---------------------------------------------------------------------------
// BC-3.03.006: High threshold — exactly 50 unit IDs
// ---------------------------------------------------------------------------

/// BC-3.03.006 (AC-002): exactly 50 distinct unit IDs must escalate severity
/// to High.
#[test]
fn test_bc_3_03_006_at_high_threshold_fires_high() {
    let ids: Vec<u8> = (1..=50).collect();
    let obs = obs_with_unit_ids("10.0.0.1", "10.0.0.2", &ids);
    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "BC-3.03.006: 50 unit IDs must produce exactly one finding"
    );
    assert_eq!(
        findings[0].severity,
        Severity::High,
        "BC-3.03.006: 50 unit IDs must escalate to High severity"
    );
}

// ---------------------------------------------------------------------------
// BC-3.03.006: High severity persists well above the escalation threshold
// ---------------------------------------------------------------------------

/// BC-3.03.006: 100 distinct unit IDs (well above High threshold) must fire
/// at High severity and produce exactly one finding.
#[test]
fn test_bc_3_03_006_well_above_high_fires_high() {
    // u8 only goes to 255; use 0..=99 for 100 IDs
    let ids: Vec<u8> = (0..=99).collect();
    let obs = obs_with_unit_ids("10.0.0.1", "10.0.0.2", &ids);
    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "BC-3.03.006: 100 unit IDs must produce exactly one finding"
    );
    assert_eq!(
        findings[0].severity,
        Severity::High,
        "BC-3.03.006: 100 unit IDs must fire at High severity"
    );
}

// ---------------------------------------------------------------------------
// BC-3.03.006: distinct (src, dst) pairs emit separate findings
// ---------------------------------------------------------------------------

/// BC-3.03.006: two `(src, dst)` pairs that each independently reach the
/// Medium threshold must each produce their own finding — total 2 findings.
#[test]
fn test_bc_3_03_006_distinct_src_dst_pairs_emit_separate_findings() {
    let mut obs = Observations::default();

    // Pair 1: 10.0.0.1 → 10.0.0.2, 5 unit IDs
    let mut unit_ids_a = BTreeSet::new();
    for i in 1u8..=5 {
        unit_ids_a.insert(i);
    }
    obs.modbus_flow_summary.insert(
        (ip("10.0.0.1"), ip("10.0.0.2")),
        ModbusFlowSummary {
            unit_ids: unit_ids_a,
        },
    );

    // Pair 2: 10.0.0.3 → 10.0.0.4, 7 unit IDs
    let mut unit_ids_b = BTreeSet::new();
    for i in 10u8..=16 {
        unit_ids_b.insert(i);
    }
    obs.modbus_flow_summary.insert(
        (ip("10.0.0.3"), ip("10.0.0.4")),
        ModbusFlowSummary {
            unit_ids: unit_ids_b,
        },
    );

    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert_eq!(
        findings.len(),
        2,
        "BC-3.03.006: two qualifying (src, dst) pairs must produce two separate findings"
    );
}

// ---------------------------------------------------------------------------
// BC-3.03.006: evidence shape — count and first 10 IDs
// ---------------------------------------------------------------------------

/// BC-3.03.006 (AC-002): evidence must include both the total count of
/// distinct unit IDs and the first 10 IDs. With 15 unit IDs (1..=15),
/// the evidence strings must contain "15" (count) and all 10 IDs in the
/// first-10 sample.
#[test]
fn test_bc_3_03_006_evidence_includes_count_and_first_10_ids() {
    let ids: Vec<u8> = (1..=15).collect();
    let obs = obs_with_unit_ids("10.0.0.1", "10.0.0.2", &ids);
    let findings = otsniff::findings::modbus_recon::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "BC-3.03.006: 15 unit IDs must produce exactly one finding"
    );

    let finding = &findings[0];
    // The evidence is a Vec<String>. At least one line must mention the count.
    let all_evidence = finding.evidence.join(" ");
    assert!(
        all_evidence.contains("15"),
        "BC-3.03.006: evidence must include the total count (15); got: {:?}",
        finding.evidence
    );

    // The first 10 IDs (1..=10) must each appear somewhere in the evidence.
    for expected_id in 1u8..=10 {
        assert!(
            all_evidence.contains(&expected_id.to_string()),
            "BC-3.03.006: evidence must include unit_id={} (first 10 IDs); got: {:?}",
            expected_id,
            finding.evidence
        );
    }
}
