---
document_type: red-gate-log
level: ops
version: "1.0"
status: complete
producer: test-writer
timestamp: 2026-05-15T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-2.02-cap-cred-events-dedup.md
  - src/observe.rs
traces_to: BC-1.03.007
stub_architect_agent: b8753c1
stub_compile_verified: true
test_writer_agent: session-S-2.02-step3
red_gate_verified: true
---

# Red Gate Log: S-2.02 — Cap `cred_events` by deduping at observation time

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-2.02 | 4 | Yes (all 4 panic on `todo!`) | PASSED |

## Tests Written

| Test Name | File | Line | AC / BC |
|-----------|------|------|---------|
| `test_bc_1_03_007_record_cred_event_dedups_same_key` | `src/observe.rs` | ~851 | AC-001-a / BC-1.03.007 |
| `test_bc_1_03_007_record_cred_event_property_n_duplicates` | `src/observe.rs` | ~874 | AC-001-b / BC-1.03.007 |
| `test_bc_1_03_007_record_cred_event_distinct_kinds_not_deduped` | `src/observe.rs` | ~896 | EC-001 / BC-1.03.007 |
| `test_bc_1_03_007_cred_events_bounded_under_1m_duplicates` | `tests/memory_bound.rs` | ~57 | AC-003 / BC-1.03.007 |

## Stubs Present (from Step 2)

- `pub fn record_cred_event(&mut self, _event: CredEvent)` in `src/observe.rs:299` — body is `todo!("S-2.02: dedup logic landing in step 4")`

## Red Gate Verification

### S-2.02 unit tests (src/observe.rs mod tests)

```
---- observe::tests::test_bc_1_03_007_record_cred_event_dedups_same_key stdout ----

thread 'observe::tests::test_bc_1_03_007_record_cred_event_dedups_same_key' panicked at src/observe.rs:299:9:
not yet implemented: S-2.02: dedup logic landing in step 4
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- observe::tests::test_bc_1_03_007_record_cred_event_distinct_kinds_not_deduped stdout ----

thread 'observe::tests::test_bc_1_03_007_record_cred_event_distinct_kinds_not_deduped' panicked at src/observe.rs:299:9:
not yet implemented: S-2.02: dedup logic landing in step 4

---- observe::tests::test_bc_1_03_007_record_cred_event_property_n_duplicates stdout ----

thread 'observe::tests::test_bc_1_03_007_record_cred_event_property_n_duplicates' panicked at src/observe.rs:299:9:
not yet implemented: S-2.02: dedup logic landing in step 4


failures:
    observe::tests::test_bc_1_03_007_record_cred_event_dedups_same_key
    observe::tests::test_bc_1_03_007_record_cred_event_distinct_kinds_not_deduped
    observe::tests::test_bc_1_03_007_record_cred_event_property_n_duplicates

test result: FAILED. 100 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

### S-2.02 integration test (tests/memory_bound.rs)

```
running 1 test
test test_bc_1_03_007_cred_events_bounded_under_1m_duplicates ... FAILED

failures:

---- test_bc_1_03_007_cred_events_bounded_under_1m_duplicates stdout ----

thread 'test_bc_1_03_007_cred_events_bounded_under_1m_duplicates' panicked at src/observe.rs:299:9:
not yet implemented: S-2.02: dedup logic landing in step 4
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    test_bc_1_03_007_cred_events_bounded_under_1m_duplicates

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 100 pre-existing lib unit tests | all pass |
| 16 cli_smoke integration tests | all pass |
| 50 snapshot integration tests | all pass |

## Visibility Changes Made (Implementer Must Know)

Two minimal changes were made to `src/observe.rs` to enable the integration test in `tests/memory_bound.rs`:

1. `record_cred_event` promoted from `fn` to `pub fn` — the integration test calls this directly to exercise the 1M-packet flood path.
2. New `pub fn observations(&self) -> &Observations` accessor added to `Observer` — the integration test reads `cred_events.len()` without needing direct field access. The `finish()` method consumes `self`, so a non-consuming accessor was needed for the mid-loop check.

EC-003 (u32 saturation at MAX) was intentionally skipped per task brief — noted here for future story.

## Hand-Off to Implementer

- Story ready for implementation: S-2.02
- Implementation target: `src/observe.rs`, `Observer::record_cred_event`
- Required behaviour: dedup by `(src_ip, dst_ip, dst_port, kind)` key; increment `count` on duplicate; must not grow `cred_events` proportional to raw packet count
- The four inline `self.obs.cred_events.push(...)` sites at lines ~396, ~409, ~423, ~515 should be replaced with `self.record_cred_event(...)` calls (Step 4)
- `observations()` accessor is now part of the public API and should be kept; do not remove it
