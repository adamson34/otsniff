# Kani Proof Execution: Deferred to CI

## Status

`cargo-kani` was not installed in the local development environment where this story was implemented. Installation is deferred per constraint L-P3-002.

The proof harness (`scrub_roundtrip_bounded` in `src/scrub.rs`) is complete and structurally verified by the acceptance script (`scripts/check-s-4-01-acceptance.sh`, 8/8 PASS). However, actual symbolic execution by the Kani model checker has not yet been run.

## Verification Path

The first actual proof run will occur when `.github/workflows/kani.yml` executes. This workflow:

1. Installs `kani-verifier` via `cargo install --locked kani-verifier`
2. Runs `cargo kani setup`
3. Executes `cargo kani --harness scrub_roundtrip_bounded` with a 30-minute timeout

The workflow triggers on:
- Weekly cron: Sunday 06:00 UTC
- Manual `workflow_dispatch` (can be triggered immediately via GitHub Actions UI)

## Story Task Acknowledgement

Story S-4.01, Task 1 explicitly notes: `[ ] Install cargo-kani (deferred per L-P3-002)`. This deferral is by design — the harness authorship and CI integration (Tasks 2-5) are complete and constitute the deliverable for this story cycle.

## What the Structural Checks Confirm

The 8-check acceptance script confirms:
- The `#[kani::proof]` attribute is present (harness is syntactically correct)
- No `todo!()` placeholder remains (implementation is substantive)
- Both `scrub_text` and `unscrub_text` are called (the round-trip property is exercised)
- The CI workflow file exists and is correctly configured
- The proof documentation exists and includes bound rationale

These checks are not a substitute for actual proof verification; they confirm the artifact is ready for CI execution.
