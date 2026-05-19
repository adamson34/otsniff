---
document_type: red-gate-log
level: ops
version: "1.0"
status: passed-red-state
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-6.01-scrub-map-merge.md
input-hash: "[sha256-not-computed]"
traces_to: "BC-5.03.001"
stub_architect_agent: "b8b566a"
stub_compile_verified: true
test_writer_agent: "session-S-6.01"
red_gate_verified: true
---

# Red Gate Log: S-6.01 — Stable pseudonym maps across captures

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-6.01 | 9 (8 lib unit + 1 CLI integration) | 8 lib FAIL; 1 CLI SKIP (fixture absent) | PASSED |

## Stubs Created

### S-6.01: Stable pseudonym maps across captures

- `pub fn merge_map(_baseline: ScrubMap, _current: &Observations) -> ScrubMap` — `todo!()` body in `src/scrub.rs`
- `pub fn validate(&self) -> crate::error::Result<()>` — `todo!()` body added to `ScrubMap` impl in `src/scrub.rs` (required for EC-001 test to compile)

## Red Gate Verification

### S-6.01

- AC-001 identity law (BC-5.03.001): `test_bc_5_03_001_merge_empty_baseline_is_identity_to_current` — FAIL (todo!() panic in merge_map)
- AC-001 preservation (BC-5.03.001): `test_bc_5_03_001_merge_preserves_baseline_pseudonyms` — FAIL (todo!() panic)
- AC-001 counter continuity (BC-5.03.001): `test_bc_5_03_001_new_identifiers_get_fresh_pseudonyms_from_max_plus_one` — FAIL (todo!() panic)
- AC-001 chained merges (BC-5.03.001): `test_bc_5_03_001_chained_merges_respect_accumulated_baseline` — FAIL (todo!() panic)
- AC-001 independent counters (BC-5.03.001): `test_bc_5_03_001_separate_counters_for_ips_macs_names` — FAIL (todo!() panic)
- AC-002 round-trip (BC-5.03.001): `test_bc_5_03_001_round_trip_after_merge_uses_baseline_pseudonyms` — FAIL (todo!() panic)
- EC-001 corrupted map (BC-5.03.001): `test_bc_5_03_001_load_rejects_map_with_empty_pseudonym` — FAIL (todo!() panic in validate())
- AC-004 leak detector (BC-5.03.001): `test_bc_5_03_001_leak_detector_passes_after_merge` — FAIL (todo!() panic in merge_map)
- AC-003 CLI (BC-5.03.001): `test_bc_5_03_001_baseline_map_flag_extends_pseudonyms` — SKIP (tests/fixtures/Modbus.pcap absent in worktree); will FAIL when fixture present because CLI stub calls build_map() instead of merge_map()

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 145 lib unit tests | all pass |
| 102 integration tests (cli_smoke + ldap_creds + memory_bound + modbus_recon + ntlmv1 + rdp_legacy + snapshot + weak_tls_cipher) | all pass |
| **247 total pre-existing** | **all pass** |

## Hand-Off to Implementer

- Stories ready for implementation: S-6.01
- Implementation guidance:
  1. Implement `merge_map` in `src/scrub.rs`: walk baseline ips/macs/names, compute max suffix per prefix (e.g. `host_005` → max=5), then for each identifier in current that is NOT already a real-value in baseline, mint a new pseudonym at max+1 and increment. Preserve all baseline entries regardless of whether they appear in current (EC-003).
  2. Implement `ScrubMap::validate` in `src/scrub.rs`: return `Err(OtError::Parse(...))` if any pseudonym key in ips, macs, or names is an empty string (EC-001).
  3. Wire `--baseline-map` in `src/cli.rs::run_scrub`: read the file at `_baseline_path`, deserialize as `ScrubMap`, call `validate()` on it (return `OtError` on failure), then call `merge_map(baseline, &obs)` instead of `build_map(&obs)`.
  4. Run `cargo test` and iterate until all 9 new tests pass without breaking the 247 pre-existing tests.
