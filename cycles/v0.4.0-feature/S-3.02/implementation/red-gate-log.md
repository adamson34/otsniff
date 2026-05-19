# Red Gate Log — S-3.02

**Story:** S-3.02 Prompt evaluation harness with rubric-based comparison
**Phase:** 3 (TDD Implementation — test-writer step)
**Date:** 2026-05-19
**Status:** PASSED red-state (all new tests fail, all pre-existing tests pass)

## Rust Test Results

**Suite:** `tests/prompt_evals.rs`

| Test | Result | Failure Reason |
|------|--------|---------------|
| `test_BC_6_02_001_must_assertion` | FAIL | `todo!("S-3.02: rubric parser lands in step 4")` |
| `test_BC_6_02_001_should_assertion` | FAIL | `todo!("S-3.02: rubric parser lands in step 4")` |
| `test_BC_6_02_001_must_not_assertion` | FAIL | `todo!("S-3.02: rubric parser lands in step 4")` |
| `test_BC_6_02_001_multiple_assertions` | FAIL | `todo!("S-3.02: rubric parser lands in step 4")` |
| `test_BC_6_02_001_rejects_malformed_input` | FAIL | `todo!("S-3.02: rubric parser lands in step 4")` |
| `test_BC_6_02_001_skips_blank_lines_and_comments` | FAIL | `todo!("S-3.02: rubric parser lands in step 4")` |
| `test_BC_AUDIT_013_parse_existing_rubric_files` | FAIL | `rubric.md missing in .../tap; implementer must create it in step 4` |

**New failures:** 7 / 7 (all fail for the correct reason — not vacuously true)
**Pre-existing passing tests:** 186 across all other test suites (0 regressions)

## Shell Acceptance Script Results

**Script:** `scripts/check-s-3-02-acceptance.sh`
**Exit code:** 1

| AC | Result | Notes |
|----|--------|-------|
| AC-001a | PASS | All 4 eval directories exist (span, host-side, tap, ambiguous) |
| AC-001b | FAIL | observations.json, rubric.md, run.sh missing from all 4 dirs (stub state) |
| AC-002a | FAIL | run_all.sh is a stub (14 lines, no real claude invocation) |
| AC-002b | FAIL | run_all.sh has no non-comment `leak` reference |
| AC-003 | PASS | README.md skeleton mentions "90%" and "MUST" in TODO text |
| AC-004 | FAIL | prompt-evals.yml is a stub (14 lines, no real claude invocation) |

## POL-12 Lint

`scripts/lint-no-user-paths.sh` — exit 0 (285 files scanned, 0 violations)

## BC Coverage

| Behavioral Contract | Tests Generated | Coverage |
|--------------------|----------------|---------|
| BC-6.02.001 (rubric parser) | 6 tests | preconditions (malformed), postconditions (Must/Should/MustNot/multiple/blank-skip) |
| BC-AUDIT-013 (on-disk rubric files) | 1 test | filesystem walk + parse-without-error + min-1-assertion |

## Hand-off to Implementer

All 7 tests fail for the correct reason. The implementer must:
1. Implement `parse_rubric(text: &str) -> Result<Vec<RubricAssertion>, String>` to make tests 1–6 pass.
2. Create `tests/prompt-evals/{span,host-side,tap,ambiguous}/rubric.md` (with real assertions) to make test 7 pass.
3. Create `observations.json` and `run.sh` in each eval dir.
4. Implement `tests/prompt-evals/run_all.sh` with real logic + leak-detector wiring.
5. Implement `.github/workflows/prompt-evals.yml` with real CI steps.

Make each test pass one at a time with minimum code.
