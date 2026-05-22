# Red Gate Log — S-3.04 (Fuzz harnesses for all parsers)

**Date:** 2026-05-22
**Worktree:** `.worktrees/S-3.04/`
**Branch:** `feature/S-3.04-fuzz-parsers`
**Stub commit:** `467acec`
**Tests commit:** `271f711`
**TDD mode:** `facade` — story deliverable is a separate `fuzz/` cargo package + main-crate regression test + CI workflow. Tests assert artifact content via `std::fs` + string matching; no new deps.

## Outcome: PASSED (Red Gate is correctly RED on behavioral checks)

- 14 tests written across 4 ACs (BC-1.02.001 through BC-1.02.005)
- 7 fail with assertion errors — these check behavioral contracts (parser binding, 64 KB cap, no TODOs, corpus seeding, regression-test artifact walk, per-parser dispatch)
- 7 pass on the stub — these check structural contracts (file existence, `[[bin]]` count, workflow YAML shape) that the skeleton scaffolds correctly by design

This split is the expected `tdd_mode: facade` pattern: scaffolding ACs are green-by-design from the stub commit; behavioral ACs require Step 4 to fill in TODO markers and real implementation.

## Failing tests (Red Gate)

| Test | BC | AC | Why it fails against stub |
|---|---|---|---|
| `test_bc_1_02_001_ac001_each_harness_calls_parser_and_bounds_input` | 001 | 001 | Stub harnesses are empty `fuzz_target!` bodies |
| `test_bc_1_02_001_ac001_no_todo_placeholders_in_fuzz_targets` | 001 | 001 | All 6 stub harnesses contain `TODO(S-3.04 step 4)` |
| `test_bc_1_02_001_ac001_no_todo_placeholders_in_fuzz_cargo_toml` | 001 | 001 | `fuzz/Cargo.toml` has `TODO` on version-pinning |
| `test_bc_1_02_002_ac002_no_todo_placeholders_remain` | 002 | 002 | 6× `TODO` markers in `fuzz.yml` |
| `test_bc_1_02_003_ac003_corpus_seed_doc_or_setup_present` | 003 | 003 | No `fuzz/corpus/`, no `README.md`, no workflow corpus step |
| `test_bc_1_02_004_ac004_fuzz_regressions_test_walks_artifacts` | 004 | 004 | `fuzz_artifacts_dont_panic` body is TODO placeholder |
| `test_bc_1_02_005_ac004_fuzz_regressions_test_handles_each_parser` | 005 | 004 | Harness names appear only in comments, not in dispatch code |

## Passing tests (scaffold-complete — green-by-design)

| Test | BC | AC | Why it passes on stub |
|---|---|---|---|
| `test_bc_1_02_001_ac001_fuzz_cargo_toml_exists_and_lists_six_binaries` | 001 | 001 | Stub already declares all 6 `[[bin]]` entries |
| `test_bc_1_02_001_ac001_each_harness_file_exists` | 001 | 001 | All 6 skeleton files present |
| `test_bc_1_02_002_ac002_fuzz_workflow_exists` | 002 | 002 | Workflow file exists |
| `test_bc_1_02_002_ac002_workflow_runs_weekly_not_pr` | 002 | 002 | Stub already has `cron: "0 2 * * 0"` and no `pull_request:` |
| `test_bc_1_02_002_ac002_workflow_runs_each_harness_60_seconds` | 002 | 002 | Stub already has `max_total_time=60` and 6-name matrix |
| `test_bc_1_02_002_ac002_workflow_uploads_crash_artifacts` | 002 | 002 | Stub already has `upload-artifact` step |
| `test_bc_1_02_004_ac004_fuzz_regressions_test_exists` | 004 | 004 | `tests/fuzz_regressions.rs` exists |

## Independent verification command

```bash
cd /Users/lukeadamson/1898/otsniff/.worktrees/S-3.04
cargo test --test s_3_04_fuzz_infrastructure
```

Output: `test result: FAILED. 7 passed; 7 failed; 0 ignored; 0 measured; 0 filtered out`

## Gate decision

✅ **Proceed to Step 4 (Implementation).** Behavioral contracts are correctly RED; scaffolding contracts are correctly GREEN-by-design (facade pattern). Implementer has 7 concrete acceptance signals to turn green.
