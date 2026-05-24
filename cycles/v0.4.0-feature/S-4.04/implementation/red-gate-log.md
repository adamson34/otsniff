# Red Gate Log — S-4.04 (Kani composed proof of the privacy invariant)

**Date:** 2026-05-23
**Worktree:** `.worktrees/S-4.04/`
**Branch:** `feature/S-4.04-kani-composed-proof`
**Stub commit:** `38b2f19`
**Tests commit:** `15e150b`
**TDD mode:** `facade` — story deliverable is a composed Kani harness + reviewer-ready summary doc. Static-content assertions stand in for actual proof execution (CI runs `cargo kani` separately).

## Outcome: PASSED (Red Gate is correctly RED on behavioral checks)

- 12 tests total
- 4 fail with assertion errors — behavioral contracts (`todo!()` removed, real unwind bound, BC-5.02.003 referenced, doc TODOs removed)
- 8 pass on the stub — structural contracts (file existence, module registration, function shape, imports, doc sections, story refs, CI wiring) that the skeleton scaffolded correctly by design

## Failing tests (Red Gate)

| Test | AC | Why it fails against stub |
|---|---|---|
| `test_ac_001_no_todo_in_composed_harness` | AC-001 | `src/kani_proofs.rs` contains `TODO(S-4.04 step 4)` and `todo!(...)` |
| `test_ac_001_has_real_unwind_bound` | AC-001 | `kani::unwind(SOME_BOUND)` — placeholder, no positive integer |
| `test_ac_002_doc_references_bc_5_02_003` | AC-002 | Reviewer doc doesn't mention BC-5.02.003 |
| `test_ac_002_doc_has_no_todo_placeholders` | AC-002 | Doc has 5 TODO blocks |

## Passing tests (scaffold-complete)

8 structural tests — file existence, `mod kani_proofs;` registration in lib.rs, `#[kani::proof]` attribute presence, both `scrub` + `leak_detector` imports, all 5 H2 section headers, story refs (S-4.01..03), CI workflow wiring.

## Independent verification

```bash
cd /Users/lukeadamson/1898/otsniff/.worktrees/S-4.04
cargo test --test s_4_04_composed_kani_proof
```

Output: `test result: FAILED. 8 passed; 4 failed; 0 ignored`

## Note on Kani CI

`cargo kani --harness composed_privacy_invariant` runs as part of `.github/workflows/kani.yml` (added in stub commit). That's what actually verifies the proof; this Red Gate confirms the static contracts (file shape, doc completeness) that gate whether the proof CAN execute.

## Gate decision

✅ **Proceed to Step 4.**
