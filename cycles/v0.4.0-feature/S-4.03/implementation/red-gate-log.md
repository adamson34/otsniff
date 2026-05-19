# Red Gate Log — S-4.03

**Story:** S-4.03 — Kani proof: `ensure_no_map_values` substring invariant
**Cycle:** v0.4.0-feature
**Status:** PASSED (red state verified)
**Date:** 2026-05-19

## Acceptance Script

`scripts/check-s-4-03-acceptance.sh` — exit code 1 (expected)

## Check Results

| Check | Result | Detail |
|-------|--------|--------|
| AC-001a | PASS | `fn map_value_substring` declared in `src/ai/leak_detector.rs` |
| AC-001b | FAIL | Body still contains `todo!()` — implementer must fill in |
| AC-001c | FAIL | `ensure_no_map_values` not called on non-comment line in `#[cfg(kani)]` block |
| AC-001d | PASS | `kani.yml` invokes `cargo kani --harness map_value_substring` on non-comment line |
| AC-002 (no-TODO) | FAIL | `docs/proofs/ensure-no-map-values.md` contains 10 TODO markers — skeleton |
| AC-002 (invariant-stated) | PASS | Doc contains "bidirectional" |
| AC-003 | PASS | Bounds mentioned in doc (`≤ 32`, table present) |

**4/7 PASS, 3/7 FAIL — exit 1. Red Gate: PASSED.**

## Pre-existing Test Suite

```
cargo test --all-features
```

- 263 tests passed, 0 failed across all crates.
- Lint: `bash scripts/lint-no-user-paths.sh` — exit 0, 324 files scanned, 0 violations.

## Failing Checks (expected before implementation)

- **AC-001b:** `map_value_substring()` body is `todo!()`. Implementer must write the symbolic harness with `kani::any()` inputs and calls to `ensure_no_map_values`.
- **AC-001c:** Harness does not yet call `ensure_no_map_values`. Required for the proof to exercise BC-5.02.002.
- **AC-002 (no-TODO):** `docs/proofs/ensure-no-map-values.md` has 10 TODO markers. Documentation is a skeleton awaiting the real proof sketch and rationale.

## Handoff to Implementer

Make each failing check pass:
1. Replace `todo!()` in `map_value_substring()` with a symbolic harness that calls `ensure_no_map_values` with `kani::any()`-derived inputs and proves the bidirectional invariant.
2. Fill in `docs/proofs/ensure-no-map-values.md` — remove all TODO markers, add proof sketch for both directions, bounds rationale, and run instructions.
3. Verify: `bash scripts/check-s-4-03-acceptance.sh` exits 0.
