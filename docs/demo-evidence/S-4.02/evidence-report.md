# Evidence Report — S-4.02

Story: S-4.02 — Kani formal verification for leak detector regexes  
Behavioral contract: BC-5.02.001 (pre-existing)  
Worktree HEAD: 28672687f077a83cdffc328507e00a7a81e015e2  
Date: 2026-05-19

## AC Coverage

| AC | File | Result |
|----|------|--------|
| AC-001: Three Kani harnesses in `#[cfg(kani)]` block | `AC-001-kani-harnesses.md` | PASS (structural) |
| AC-002: CI workflow has 3 new `cargo kani --harness` steps | `AC-002-ci-workflow.md` | PASS (structural) |
| AC-003: `docs/proofs/leak-detector-regex.md` fully filled in | `AC-003-proof-doc.md` | PASS (structural) |
| Acceptance script 12/12 | `acceptance-script-run.md` | PASS |

## Notes

- Proof execution deferred to CI — see `kani-deferred-note.md`.
- All structural checks verified locally via `scripts/check-s-4-02-acceptance.sh` (12/12 PASS).
- BC-5.02.001 is pre-existing; S-4.02 adds machine-checked coverage for the regex layer.
