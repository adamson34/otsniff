# Evidence Report: S-4.01

**Story:** S-4.01 — Kani proof: `unscrub(scrub(x, map), map) == x`
**Story ID:** S-4.01
**Behavioral Contract:** BC-5.01.003
**Worktree HEAD SHA:** 760bdcf97775efa64df89a2287b2f8af0ab11ab7
**Date:** 2026-05-19
**Branch:** feature/S-4.01-kani-scrub-round-trip

## AC Coverage

| AC | Description | Evidence File | Structural Result | Proof Result |
|----|-------------|--------------|-------------------|--------------|
| AC-001 | Kani harness in src/scrub.rs proves round-trip (N=8, K=1) | AC-001-kani-harness.md | PASS (8 structural checks) | Deferred to CI |
| AC-002 | CI workflow .github/workflows/kani.yml (weekly schedule) | AC-002-ci-workflow.md | PASS | N/A |
| AC-003 | docs/proofs/scrub-roundtrip.md with bound rationale | AC-003-proof-doc.md | PASS | N/A |

## Acceptance Script

All 8/8 checks pass. See `acceptance-script-run.md`.

## Proof Verification Deferral

`cargo-kani` is not installed locally (deferred per L-P3-002, Story Task #1). The harness is structurally complete and CI-ready. First execution via `workflow_dispatch` on `.github/workflows/kani.yml` constitutes the actual verification. See `kani-deferred-note.md`.

## Files

- `AC-001-kani-harness.md` — harness code excerpt + run command
- `AC-002-ci-workflow.md` — full kani.yml content
- `AC-003-proof-doc.md` — docs/proofs/scrub-roundtrip.md content
- `acceptance-script-run.md` — check script output (8/8 PASS)
- `kani-deferred-note.md` — deferral rationale
- `evidence-report.md` — this file
