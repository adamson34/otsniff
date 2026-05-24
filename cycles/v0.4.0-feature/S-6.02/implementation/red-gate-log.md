# Red Gate Log — S-6.02 (`otsniff diff` subcommand + delta computation)

**Date:** 2026-05-23
**Worktree:** `.worktrees/S-6.02/`
**Branch:** `feature/S-6.02-diff-subcommand`
**Stub commit:** `05feda4`
**Tests commit:** `d45f7de`
**TDD mode:** `strict` (first non-facade story in wave-2)

## Outcome: PASSED (Red Gate correctly RED on behavioral checks)

- 16 tests total
- 13 fail with `todo!()` panic or assertion errors — these are the actual behavioral contracts for `compute()` and the diff data
- 3 pass on the stub — CLI surface tests that exercise clap parsing (the Diff enum variant is wired enough for `--help` to work; the dispatch arm is `todo!()` but those tests don't invoke it)

This split matches strict-TDD semantics: the API surface compiles (because the stub declared the right types) but every test that calls into `compute` panics on `todo!()` — exactly what should happen before implementation.

## Failing tests (Red Gate)

| Test | AC | BC | Expected failure |
|---|---|---|---|
| `test_ac_002_host_added_appears_in_hosts_new` | 002 | 3.08.001 | `todo!()` |
| `test_ac_002_identification_by_pseudonym_not_ip` | 002 | 3.08.001 | `todo!()` — load-bearing for pseudonym identity |
| `test_ac_002_empty_intersection_is_all_new_and_all_gone` | 002 EC-001 | 3.08.001 | `todo!()` |
| `test_ac_003_finding_new_in_current_only_is_in_findings_new` | 003 | 3.08.002 | `todo!()` |
| `test_ac_003_finding_in_both_is_findings_recurring` | 003 | 3.08.002 | `todo!()` |
| `test_ac_003_finding_only_in_baseline_is_findings_resolved` | 003 | 3.08.002 | `todo!()` |
| `test_ac_003_matching_by_exact_tuple_no_near_matches` | 003 | 3.08.002 | `todo!()` |
| `test_ac_004_role_shift_detected` | 004 | 3.08.003 | `todo!()` |
| `test_ac_004_no_role_shift_when_role_unchanged` | 004 | 3.08.003 | `todo!()` |
| `test_ac_004_new_flow_pair_appears_in_flow_shifts` | 004 | 3.08.003 | `todo!()` |
| `test_ac_004_flow_volume_doubled_triggers_shift` | 004 | 3.08.003 | `todo!()` |
| `test_ac_004_flow_volume_minor_change_not_in_shifts` | 004 | 3.08.003 | `todo!()` |
| `test_ec_002_maps_with_no_shared_pseudonyms_warns_and_proceeds` | EC-002 | 3.08.001 | `todo!()` |

## Passing tests (CLI surface — already wired by stub)

| Test | AC | Why it passes |
|---|---|---|
| `test_ac_001_diff_subcommand_in_help` | 001 | Enum variant exists |
| `test_ac_001_diff_subcommand_help_documents_args` | 001 | clap exposes args from struct fields |
| `test_ac_001_diff_missing_args_fails_with_usage` | 001 | clap rejects before dispatch |

## API note from test-writer (carry into Step 4)

`DiffInput` was extended to include `findings: &'a [Finding]` so `compute` can compare pre-computed findings. Implementer must wire finding-tuple extraction in `compute` — tuple key is `(rule_id, src_pseudonym, dst_pseudonym, dst_port)`. Two options for getting the tuple from a `Finding`:
- Structured key extractor (preferred — add a `pub fn key(&self) -> (String, String, String, u16)` to `Finding`)
- Parse from evidence/summary strings (fragile, avoid)

Role-shift tests drive role via protocols in `HostObs` and expect `compute` to call `inventory::infer_role` on each side.

Flow-shift detection: join `Observations.flows` keyed by pseudonymized `(src, dst, dst_port, proto)`.

## Independent verification

```bash
cd /Users/lukeadamson/1898/otsniff/.worktrees/S-6.02
cargo test --test s_6_02_diff_subcommand
```

Output: `test result: FAILED. 3 passed; 13 failed; 0 ignored`

## Gate decision

✅ **Proceed to Step 4.**
