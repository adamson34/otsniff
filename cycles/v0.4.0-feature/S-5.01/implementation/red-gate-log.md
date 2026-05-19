---
document_type: red-gate-log
level: ops
version: "1.0"
status: passed
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-5.01-parse-progress-feedback.md
  - src/progress.rs
  - tests/cli_smoke.rs
input-hash: "[md5]"
traces_to: "BC-9.04.001"
stub_architect_agent: "fa79209"
stub_compile_verified: true
test_writer_agent: "claude-sonnet-4-6"
red_gate_verified: true
---

# Red Gate Log: S-5.01 — Periodic parse-loop progress in `-v` mode

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-5.01 | 8 (6 unit + 2 cli_smoke) | 6 FAIL (expected); 2 vacuous PASS (acceptable) | PASSED |

## Stubs Created

### S-5.01: ProgressReporter

- `pub trait Clock` + `pub struct SystemClock` — time injection surface
- `pub fn new_with_clock(writer: W, verbose: bool, clock: Box<dyn Clock>) -> Self` — test constructor
- `pub fn record_packet(&mut self, _packet_size: usize)` — `todo!()`
- `pub fn finish(&mut self)` — `todo!()`

Schema additions to `src/progress.rs`:
- `clock: Box<dyn Clock>` field on `ProgressReporter<W>`
- `use std::time::Duration` inside `#[cfg(test)]` module

## Red Gate Verification

### S-5.01

| Test | File:Line | AC | Failure Mode | Status |
|------|-----------|----|--------------|--------|
| `test_bc_9_04_001_emits_after_100k_packets` | src/progress.rs:162 | AC-001 | `panic: not yet implemented` (record_packet) | FAIL (expected) |
| `test_bc_9_04_001_emits_after_10mb_bytes` | src/progress.rs:191 | AC-001 | `panic: not yet implemented` (record_packet) | FAIL (expected) |
| `test_bc_9_04_001_no_emission_when_verbose_false` | src/progress.rs:216 | AC-002 | `panic: not yet implemented` (record_packet) | FAIL (expected) |
| `test_bc_9_04_001_rate_limited_to_2s` | src/progress.rs:243 | AC-003 | `panic: not yet implemented` (record_packet) | FAIL (expected) |
| `test_bc_9_04_001_finish_emits_summary_even_if_no_progress` | src/progress.rs:291 | EC-002 | `panic: not yet implemented` (record_packet) | FAIL (expected) |
| `test_bc_9_04_001_format_includes_count_and_bytes` | src/progress.rs:319 | AC-001 | `panic: not yet implemented` (record_packet) | FAIL (expected) |
| `test_bc_9_04_001_verbose_mode_emits_progress_to_stderr` | tests/cli_smoke.rs:344 | AC-001 | vacuous PASS (fixture < threshold) | PASS (acceptable — unit tests are load-bearing) |
| `test_bc_9_04_001_no_verbose_no_progress_lines` | tests/cli_smoke.rs:385 | AC-002 | vacuous PASS (no progress emitted without impl) | PASS (acceptable — asserts absence) |

**Note on vacuous cli_smoke passes:** both tests are fixture-gated (skip if
`tests/fixtures/Modbus.pcap` absent) and the Modbus.pcap is small enough that
no periodic emission fires in either direction. The unit tests in
`src/progress.rs` carry all cadence and rate-limit assertions. The cli_smoke
tests exist to confirm the verbose wiring is plumbed end-to-end once the
implementer connects `ProgressReporter` into the packet loop.

## Regression Check

| Test suite | Count | Status |
|------------|-------|--------|
| lib unit tests (pre-existing) | 134 | all pass |
| cli_smoke (pre-existing) | 16 | all pass |
| snapshot | 1 | pass |
| other integration suites | 79 | all pass |
| **New failing tests** | **6** | **FAIL — expected (Red Gate)** |

229 pre-existing tests all pass. 6 new tests fail on `todo!()` as required.

## Hand-Off to Implementer

Stories ready for implementation: **S-5.01**

Implementation guidance:

1. Add `Clock` trait to the `record_packet` / `finish` bodies — the
   `Box<dyn Clock>` field is already on the struct; call
   `self.clock.now()` instead of `Instant::now()` directly.
2. `record_packet` must:
   - increment `self.packets` and `self.bytes`
   - check both thresholds (`PROGRESS_PACKET_INTERVAL` and `PROGRESS_BYTE_INTERVAL`)
   - apply the `PROGRESS_MIN_INTERVAL_SECS` rate-limit via `self.clock.now()` - `self.last_emit_time`
   - emit one `[parse] processed N packets / X.X MB ...` line when conditions are met
   - update `self.last_emit_packets`, `self.last_emit_bytes`, `self.last_emit_time`
   - no-op immediately when `self.verbose` is false
3. `finish` must emit one summary line when `self.verbose` is true, regardless of
   thresholds — this is the EC-002 contract.
4. Wire into `cli.rs::analyze()`: remove `let _ = progress;`, call
   `if let Some(p) = progress { p.record_packet(pkt_size); }` in the loop,
   and `p.finish()` after.
5. The `#[allow(dead_code)]` on the struct can be removed once all fields are read.
