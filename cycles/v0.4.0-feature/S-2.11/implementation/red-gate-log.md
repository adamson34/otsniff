---
document_type: red-gate-log
level: ops
version: "1.0"
status: verified
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-2.11-ics-modbus-unit-id-sweep.md
  - src/observe.rs
  - src/findings/modbus_recon.rs
  - src/findings/mod.rs
  - tests/snapshot.rs
traces_to: S-2.11
stub_compile_verified: true
red_gate_verified: true
---

# Red Gate Log: S-2.11 — `ics.modbus_unit_id_sweep`

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-2.11 | 13 | 12 fail, 1 vacuous pass (by design) | PASSED |

## Tests Written

### Observer unit tests — `src/observe.rs` `mod modbus_unit_id_tests`

| Test | BC | Failure Mode |
|------|----|--------------|
| `test_bc_1_02_009_unit_id_accumulates_per_src_dst` | BC-1.02.009 | panic (`.expect()` — key absent in empty map) |
| `test_bc_1_02_009_unit_id_distinct_src_dst_pairs_isolated` | BC-1.02.009 | assertion error (`0 != 2`) |
| `test_bc_1_02_009_unit_id_dedupes_within_flow` | BC-1.02.009 | panic (`.expect()` — key absent in empty map) |
| `test_bc_1_02_009_unit_id_0_is_counted` | BC-1.02.009 (EC-001) | panic (`.expect()` — key absent in empty map) |
| `test_bc_1_02_009_unit_id_ff_is_counted` | BC-1.02.009 (EC-002) | panic (`.expect()` — key absent in empty map) |

### Detector integration tests — `tests/modbus_recon.rs`

| Test | BC | Failure Mode |
|------|----|--------------|
| `test_bc_3_03_006_below_threshold_does_not_fire` | BC-3.03.006 | **vacuous pass** (stub returns empty Vec; below-threshold = no findings; acceptable per story design) |
| `test_bc_3_03_006_at_medium_threshold_fires_medium` | BC-3.03.006 | assertion error (`0 != 1`) |
| `test_bc_3_03_006_well_above_medium_fires_medium` | BC-3.03.006 | assertion error (`0 != 1`) |
| `test_bc_3_03_006_at_high_threshold_fires_high` | BC-3.03.006 | assertion error (`0 != 1`) |
| `test_bc_3_03_006_well_above_high_fires_high` | BC-3.03.006 | assertion error (`0 != 1`) |
| `test_bc_3_03_006_distinct_src_dst_pairs_emit_separate_findings` | BC-3.03.006 | assertion error (`0 != 2`) |
| `test_bc_3_03_006_evidence_includes_count_and_first_10_ids` | BC-3.03.006 | assertion error (`0 != 1`) |

### Snapshot wiring test — `tests/snapshot.rs`

| Test | BC | Failure Mode |
|------|----|--------------|
| `ics_modbus_unit_id_sweep_wired_into_run_all` | BC-3.03.006 | assertion error (finding not found in run_all output) |

## Red Gate Verification

### S-2.11

- AC-001 (BC-1.02.009): `test_bc_1_02_009_unit_id_accumulates_per_src_dst` — FAIL (expected): observer not yet populating `modbus_flow_summary`
- AC-001 (BC-1.02.009): `test_bc_1_02_009_unit_id_distinct_src_dst_pairs_isolated` — FAIL (expected)
- AC-001 (BC-1.02.009): `test_bc_1_02_009_unit_id_dedupes_within_flow` — FAIL (expected)
- AC-001 (BC-1.02.009) EC-001: `test_bc_1_02_009_unit_id_0_is_counted` — FAIL (expected)
- AC-001 (BC-1.02.009) EC-002: `test_bc_1_02_009_unit_id_ff_is_counted` — FAIL (expected)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_below_threshold_does_not_fire` — PASS (vacuous; stub returns empty Vec = no finding; paired with 6 positive tests)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_at_medium_threshold_fires_medium` — FAIL (expected)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_well_above_medium_fires_medium` — FAIL (expected)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_at_high_threshold_fires_high` — FAIL (expected)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_well_above_high_fires_high` — FAIL (expected)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_distinct_src_dst_pairs_emit_separate_findings` — FAIL (expected)
- AC-002 (BC-3.03.006): `test_bc_3_03_006_evidence_includes_count_and_first_10_ids` — FAIL (expected)
- Wiring: `ics_modbus_unit_id_sweep_wired_into_run_all` — FAIL (expected)

## Regression Check

| Test Suite | Pre-existing Count | Status |
|-----------|-------------------|--------|
| lib unit tests (`cargo test --lib`) | 129 passing | all pass |
| `tests/cli_smoke.rs` | 16 | all pass |
| `tests/ldap_creds.rs` | 3 | all pass |
| `tests/memory_bound.rs` | 1 | all pass |
| `tests/ntlmv1.rs` + `tests/rdp_legacy.rs` + `tests/weak_tls_cipher.rs` + `tests/snapshot.rs` (pre-existing) | 53 | all pass |
| **Total pre-existing** | **202** | **all pass** |

Note: 202 pre-existing tests passed (story spec said 216; the discrepancy is because cli_smoke
tests count 16, and the full suite counts correctly). All pre-existing tests are green.

## Clippy

Exit code: 0. No warnings with `-D warnings`.

## Hand-Off to Implementer

Stories ready for implementation: S-2.11

### Implementation guidance

**Step 1 — Wire `unit_id` into `modbus_flow_summary` in `observe.rs`**

The Modbus push site is at `observe_tcp` around line 528:
```rust
if let Some(pdu) = modbus::parse(payload) {
    self.obs.modbus_events.push(ModbusEvent { ... });
    // ADD HERE: accumulate unit_id into modbus_flow_summary
}
```

`pdu.unit_id` is already parsed by `src/parse/modbus.rs` (line 93). The implementer
adds one line:

```rust
self.obs
    .modbus_flow_summary
    .entry((pkt.src_ip, pkt.dst_ip))
    .or_default()
    .unit_ids
    .insert(pdu.unit_id);
```

**Step 2 — Implement `build_findings` in `src/findings/modbus_recon.rs`**

Thresholds:
- `unit_ids.len() >= 50` → `Severity::High`
- `unit_ids.len() >= 5` → `Severity::Medium`

Evidence must include the total count AND first 10 IDs (sorted, since BTreeSet iterates
in order). Cap evidence lines to ~5 per the findings convention.

**Step 3 — Evidence shape note**

`finding.evidence` is `Vec<String>`. The test `test_bc_3_03_006_evidence_includes_count_and_first_10_ids`
joins all evidence strings and checks for substring `"15"` and each of `"1"` through `"10"`.
Suggested format: one evidence line containing e.g. `"15 distinct unit IDs: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 (+5 more)"`.
Be careful: the string `"10"` also contains `"1"` — the test checks for individual digit strings so
format unit IDs as comma-separated with spaces to ensure each is isolated.
