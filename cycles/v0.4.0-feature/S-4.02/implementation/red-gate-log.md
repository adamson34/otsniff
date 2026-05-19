# Red Gate Log — S-4.02

**Status:** PASSED (correctly red)
**Date:** 2026-05-19
**Story:** S-4.02 — Kani proof: leak detector regex matches every IPv4/IPv6/MAC-shaped substring
**Script:** `scripts/check-s-4-02-acceptance.sh`
**Stub commit:** `3aaf86b`

## Acceptance Check Results

| Check | ID | Result |
|-------|----|--------|
| kani_proofs module exists in leak_detector.rs | AC-001a | PASS |
| harness `leak_regex_ipv4` declared | AC-001b | PASS |
| harness `leak_regex_ipv6` declared | AC-001b | PASS |
| harness `leak_regex_mac` declared | AC-001b | PASS |
| `leak_regex_ipv4` body filled in (no todo!()) | AC-001c | FAIL (correctly red) |
| `leak_regex_ipv6` body filled in (no todo!()) | AC-001d | FAIL (correctly red) |
| `leak_regex_mac` body filled in (no todo!()) | AC-001e | FAIL (correctly red) |
| cfg(kani) block calls detector entry point | AC-001f | FAIL (correctly red) |
| kani.yml invokes `cargo kani --harness leak_regex_ipv4` | AC-002a | PASS |
| kani.yml invokes `cargo kani --harness leak_regex_ipv6` | AC-002a | PASS |
| kani.yml invokes `cargo kani --harness leak_regex_mac` | AC-002a | PASS |
| docs/proofs/leak-detector-regex.md has 0 TODO markers | AC-003 | FAIL (correctly red) |

**Summary:** 7/12 passed, 5 failed. Exit code: 1.

## Pre-existing test suite

`cargo test --all-features` — 263 tests, 0 failures. Pre-existing tests unaffected.

## Lint

`scripts/lint-no-user-paths.sh` — 316 files scanned, 0 user-path violations. Exit 0.

## Why the failing checks are correct

- **AC-001c/d/e:** All three Kani harness bodies contain `todo!()` in the stub. The implementer must replace them with real symbolic proofs.
- **AC-001f:** The `#[cfg(kani)]` block contains no non-comment call to `scan()`, `ensure_clean()`, or `detect_leaks()`. Calls appear only in doc-comment lines describing the expected postcondition. The implementer must add real call-sites.
- **AC-003:** `docs/proofs/leak-detector-regex.md` contains 8 `TODO` markers. The implementer must fill in bounds rationale, harness documentation, and limitations.

## Handoff to Implementer

Make each of the 5 failing checks pass:

1. Replace `todo!()` in `leak_regex_ipv4` with a Kani symbolic proof that calls `scan()` and asserts `Some(Leak { kind: LeakKind::Ipv4, .. })`.
2. Replace `todo!()` in `leak_regex_ipv6` with a Kani symbolic proof calling `scan()`.
3. Replace `todo!()` in `leak_regex_mac` with a Kani symbolic proof calling `scan()`.
4. Ensure the `#[cfg(kani)]` block contains at least one non-comment call to `scan()`, `ensure_clean()`, or `detect_leaks()` (satisfied by steps 1–3).
5. Remove all `TODO` markers from `docs/proofs/leak-detector-regex.md` and fill in bounds rationale.

The workflow steps in `.github/workflows/kani.yml` are already correct and will pass once the harnesses are implemented.
