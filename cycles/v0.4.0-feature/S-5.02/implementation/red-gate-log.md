---
document_type: red-gate-log
level: ops
version: "1.0"
status: red-state
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - src/ai/claude_cli.rs
  - .factory/stories/S-5.02-claude-heartbeat.md
input-hash: "[md5]"
traces_to: BC-6.04.001
stub_architect_agent: "8fdb65a"
stub_compile_verified: true
test_writer_agent: "claude-sonnet-4-6"
red_gate_verified: true
---

# Red Gate Log: S-5.02 — Claude invocation heartbeat

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-5.02 | 5 | YES | PASSED |

## Stubs Created

### S-5.02: Claude invocation heartbeat

- `pub(crate) fn run_with_heartbeat<W, C, T, R>(label, task, writer, clock, verbose) -> Result<R>`
  — generic-task heartbeat coordinator; body is `todo!("S-5.02: heartbeat thread lands in step 4")`

Note: signature refactored from the initial stub (which accepted `prompt`, `model`, `system_prompt`
directly) to accept a generic `task: T` closure per Approach A — makes the heartbeat machinery
testable without spawning a real subprocess.

## Red Gate Verification

### S-5.02

- AC-001 (BC-6.04.001): `test_bc_6_04_001_emits_heartbeat_every_3s` — FAIL (panicked on `todo!()`)
- AC-002 (BC-6.04.001): `test_bc_6_04_001_no_heartbeat_for_fast_task` — FAIL (panicked on `todo!()`)
- AC-001 format (BC-6.04.001): `test_bc_6_04_001_summary_includes_duration_and_byte_count` — FAIL (panicked on `todo!()`)
- AC-004 (BC-6.04.001): `test_bc_6_04_001_silent_when_not_verbose` — FAIL (panicked on `todo!()`)
- EC-002 (BC-6.04.001): `test_bc_6_04_001_propagates_task_error` — FAIL (panicked on `todo!()`)

All 5 tests panic at `src/ai/claude_cli.rs:134` with message:
`not yet implemented: S-5.02: heartbeat thread lands in step 4`

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 140 lib unit tests | all pass |
| 18 cli_smoke integration tests | all pass |
| 54 snapshot integration tests | all pass |
| 237 total pre-existing tests | all pass |

## Hand-Off to Implementer

- Stories ready for implementation: S-5.02
- Implementation guidance:
  - Implement `run_with_heartbeat` in `src/ai/claude_cli.rs`
  - Spawn `task` on a background thread via `std::thread::spawn`
  - Drive a heartbeat loop on the calling thread: poll `clock.now()` every ~100 ms,
    emit `[Ns] <label> still working...` to `writer` when elapsed crosses 3 s boundaries
  - On thread join: emit `done in Xs, N bytes response` to `writer`
  - Gate all writes on `verbose == true`
  - Propagate `task` errors through `JoinHandle::join().unwrap()` result
  - `MockClock` is defined inline in `mod tests`; cross-thread synchronisation uses
    busy-wait + `advance()` from a separate advancer thread
