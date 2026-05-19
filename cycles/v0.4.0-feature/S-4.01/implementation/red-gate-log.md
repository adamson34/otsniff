---
document_type: red-gate-log
level: ops
version: "1.0"
status: verified
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-4.01-kani-scrub-round-trip.md
  - src/scrub.rs
  - .github/workflows/kani.yml
  - docs/proofs/scrub-roundtrip.md
  - scripts/check-s-4-01-acceptance.sh
input-hash: "[computed at write time]"
traces_to: "BC-5.01.003,L-P1-004"
stub_architect_agent: "n/a (facade story — structural shell checks only)"
stub_compile_verified: true
test_writer_agent: "claude-sonnet-4-6"
red_gate_verified: true
---

# Red Gate Log: S-4.01 — Kani proof — unscrub(scrub(x, map), map) == x

## Summary

| Story  | Tests Written | All Fail (Red)? | Gate |
|--------|---------------|-----------------|------|
| S-4.01 | 1 shell script (8 AC checks across 3 ACs) | Yes — exit 1 | PASSED (correctly red) |

## Stubs Created

None. This is a `tdd_mode: facade` story. The acceptance check is a shell
script asserting structural properties of the Kani harness, workflow YAML,
and proof documentation. No Rust unit tests are written.

Stub state committed at `8b6f1cd`:
- `src/scrub.rs` — `#[cfg(kani)] mod kani_proofs { #[kani::proof] fn scrub_roundtrip_bounded() { todo!() } }`
- `.github/workflows/kani.yml` — placeholder `echo "TODO"` step, no real `cargo kani --harness` invocation
- `docs/proofs/scrub-roundtrip.md` — skeleton with TODO rationale cells in the bounds table

## Red Gate Verification

### S-4.01

Acceptance script: `scripts/check-s-4-01-acceptance.sh`

| AC | Description | Result |
|----|-------------|--------|
| AC-001a | `#[kani::proof]` attribute present in src/scrub.rs | PASS |
| AC-001b | Proof body does not contain `todo!()` (real body) | FAIL (expected — stub has todo!()) |
| AC-001c | `#[cfg(kani)]` block calls both `scrub_text` and `unscrub_text` | FAIL (expected — stub body is empty) |
| AC-002a | `.github/workflows/kani.yml` exists | PASS |
| AC-002b | kani.yml contains `cargo kani --harness` on non-comment line | FAIL (expected — stub uses echo "TODO") |
| AC-002c | kani.yml contains `cron:` schedule | PASS |
| AC-003a | `docs/proofs/scrub-roundtrip.md` exists | PASS |
| AC-003b | Bounds table rationale filled in (no `TODO` cells) | FAIL (expected — skeleton has `| TODO |` in N and K rows) |

Script exit code: **1** (correctly red).

## Regression Check

| Existing Tests | Status |
|----------------|--------|
| 263 pre-existing tests (cargo test --all-features) | all pass — 0 broken |
| scripts/lint-no-user-paths.sh | exit 0 — 308 files scanned, 0 violations |

## Hand-Off to Implementer

Stories ready for implementation: S-4.01

Implementation guidance:
1. Install cargo-kani: `cargo install --locked kani-verifier && cargo kani setup`
   (deferred per L-P3-002 — implementer installs as needed).
2. Replace `todo!()` in `scrub_roundtrip_bounded()` with a real Kani harness
   body using `kani::any::<...>()` to construct bounded symbolic inputs.
   The harness must call both `scrub_text` and `unscrub_text` and assert
   the round-trip property (AC-001b, AC-001c).
3. Tune bounds N and K until `cargo kani --harness scrub_roundtrip_bounded`
   completes in < 20 min. Document the final values and rationale in
   `docs/proofs/scrub-roundtrip.md`, replacing the `TODO` cells (AC-003b).
4. Replace the `echo "TODO"` step in `.github/workflows/kani.yml` with a
   real `cargo kani --harness scrub_roundtrip_bounded` invocation (AC-002b).
5. After each change, re-run `bash scripts/check-s-4-01-acceptance.sh`
   until exit 0.
