# Acceptance Script Run

**Command:** `bash scripts/check-s-4-01-acceptance.sh 2>&1`

```
PASS: AC-001a: src/scrub.rs contains #[kani::proof] attribute
PASS: AC-001b: Kani proof body does not contain todo!() (real implementation present)
PASS: AC-001c: #[cfg(kani)] block calls both scrub_text and unscrub_text (round-trip exercised)
PASS: AC-002a: .github/workflows/kani.yml exists
PASS: AC-002b: kani.yml contains 'cargo kani --harness' on a non-comment line
PASS: AC-002c: kani.yml contains a cron: schedule (weekly)
PASS: AC-003a: docs/proofs/scrub-roundtrip.md exists
PASS: AC-003b: docs/proofs/scrub-roundtrip.md documents N = and K = bounds with filled-in rationale

Results: 8/8 checks passed, 0 failed.
```

All 8 structural acceptance checks pass. Proof execution deferred to first CI run (see `kani-deferred-note.md`).
