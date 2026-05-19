---
document_type: red-gate-log
level: ops
version: "1.0"
status: verified
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-3.05-codecov-coverage-reporting.md
  - .github/workflows/ci.yml
  - README.md
input-hash: "[computed at write time]"
traces_to: "BC-build.001"
stub_architect_agent: "n/a (facade story — no Rust stubs)"
stub_compile_verified: false
test_writer_agent: "claude-sonnet-4-6"
red_gate_verified: true
---

# Red Gate Log: S-3.05 — Wire codecov coverage reporting into CI + add badge

## Summary

| Story  | Tests Written | All Fail (Red)? | Gate          |
|--------|---------------|-----------------|---------------|
| S-3.05 | 1 shell script (6 ACs) | Yes — exit 1 | PASSED (correctly red) |

## Stubs Created

None. This is a `tdd_mode: facade` story. Deliverables are YAML/Markdown
files. The acceptance check is a shell script asserting structural
properties of those files.

## Red Gate Verification

### S-3.05

Acceptance script: `scripts/check-s-3-05-acceptance.sh`

| AC   | BC           | Description                                          | Result            |
|------|--------------|------------------------------------------------------|-------------------|
| AC-001 | BC-build.001 | coverage job exists in ci.yml with codecov@v4 + llvm-cov | FAIL (expected) |
| AC-002 | BC-build.001 | no CODECOV_TOKEN secret in codecov step              | PASS (vacuous — step absent) |
| AC-003 | BC-build.001 | codecov.yml exists with required keys                | FAIL (expected) |
| AC-004 | BC-build.001 | README.md contains codecov badge URL                 | FAIL (expected) |
| AC-005 | BC-build.001 | 7 existing CI job keys present (no regression)       | PASS |
| AC-006 | BC-build.001 | Badge URL resolves post-merge                        | SKIP (deferred) |

Script exit code: **1** (correctly red).

Note on AC-002 vacuous pass: the codecov action step does not yet exist,
so the `token:` absence check is trivially true. This is the expected
pre-implementation state — AC-001 already captures the positive signal.
After implementation, AC-002 will run against a real step sub-block.

## Regression Check

| Existing Tests | Status       |
|----------------|--------------|
| 256 pre-existing tests (cargo test --all-features) | all pass — 0 broken |
| scripts/lint-no-user-paths.sh | exit 0 — 250 files scanned, 0 violations |

## Hand-Off to Implementer

Stories ready for implementation: S-3.05

Implementation guidance:
1. Add `coverage:` job to `.github/workflows/ci.yml` — install
   `cargo-llvm-cov` + `llvm-tools-preview` component, run
   `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info`,
   upload via `codecov/codecov-action@v4` with no `token:` input.
2. Create `codecov.yml` at repo root per AC-003 (must contain
   `coverage:`, `status:`, `comment:`, `ignore:`, `tests/**`,
   `target: 70%`).
3. Add codecov badge to `README.md` badge row:
   URL must contain `codecov.io/gh/adamson34/otsniff`.
4. After each change, re-run `bash scripts/check-s-3-05-acceptance.sh`
   until exit 0.
5. No `CODECOV_TOKEN` secret — public repo OIDC tokenless upload.
