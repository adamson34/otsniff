---
document_type: red-gate-log
level: ops
version: "1.0"
status: PASSED
producer: test-writer
timestamp: 2026-05-15T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-3.06-macos-ci-flake-investigation.md
  - .github/workflows/ci.yml
  - docs/ci-investigations/2026-05-macos-rustup-flake.md
traces_to: S-3.06
test_writer_agent: claude-sonnet-4-6
red_gate_verified: true
---

# Red Gate Log: S-3.06 macOS CI Flake Investigation

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|-------------|-----------------|------|
| S-3.06 | 6 shell-based acceptance checks | YES — all 6 FAIL | PASSED (correctly red) |

## Stubs Created

None — this is a `tdd_mode: facade` ops story. No Rust function stubs are
needed. The acceptance check is a shell script that verifies documentation
shape and CI YAML structure.

### S-3.06: Stop the recurring macOS rustup-init/cargo flake in CI

- `scripts/check-s-3-06-acceptance.sh` — shell acceptance check for all ACs
  - AC-001-a: investigation doc exists with zero TODO markers
  - AC-001-b: Flake occurrences table has >= 3 non-TODO data rows
  - AC-001-c: Non-TODO `## Root cause hypothesis` and `## Chosen fix` sections
  - AC-002: `test-macos` job does not contain `Swatinem/rust-cache`; other jobs retain it
  - AC-003: Non-TODO `## Rollback plan` section

## Red Gate Verification

### S-3.06

Script: `scripts/check-s-3-06-acceptance.sh`
Run from worktree root (`/Users/lukeadamson/1898/otsniff/.worktrees/S-3.06`):

```
$ bash scripts/check-s-3-06-acceptance.sh; echo "Exit code: $?"
FAIL: AC-001-a: docs/ci-investigations/2026-05-macos-rustup-flake.md exists but contains 10 TODO marker(s)
FAIL: AC-001-b: Flake occurrences table has 0 non-TODO data row(s) — need at least 3
FAIL: AC-001-c (root cause): '## Root cause hypothesis' section contains TODO placeholder(s) — not yet filled in
FAIL: AC-001-c (chosen fix): '## Chosen fix' section contains TODO placeholder(s) — not yet filled in
FAIL: AC-002: test-macos job still contains Swatinem/rust-cache (must be removed)
FAIL: AC-003: '## Rollback plan' section contains TODO placeholder(s) — not yet filled in

Results: 0/6 checks passed, 6 failed.
Exit code: 1
```

All 6 checks fail as expected. The Red Gate is correctly red.

### Failure Rationale per Check

| Check | Reason for Failure (Pre-Implementation) |
|-------|----------------------------------------|
| AC-001-a | `docs/ci-investigations/2026-05-macos-rustup-flake.md` is a stub with 10 TODO markers |
| AC-001-b | Flake occurrences table has only 1 row and it contains TODO |
| AC-001-c (root cause) | `## Root cause hypothesis` section body contains TODO text |
| AC-001-c (chosen fix) | `## Chosen fix` section body contains TODO text |
| AC-002 | `.github/workflows/ci.yml` `test-macos` job still includes `Swatinem/rust-cache@v2` |
| AC-003 | `## Rollback plan` section body contains TODO text |

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| Rust unit + integration tests (`cargo test`) | Not run (out of scope for this facade story — no Rust code changed) |
| `scripts/lint-no-user-paths.sh` | Not applicable (acceptance script uses relative paths internally via `SCRIPT_DIR`) |

## Hand-Off to Implementer

- Stories ready for implementation: **S-3.06**
- Implementation guidance:
  1. Fill in `docs/ci-investigations/2026-05-macos-rustup-flake.md` — replace all TODO placeholders with real investigation findings. The Flake occurrences table must have at least 3 rows with real dates, run IDs, and runner image labels.
  2. Remove the `Swatinem/rust-cache@v2` step (and any `with:` block scoped to it) from the `test-macos:` job in `.github/workflows/ci.yml`. The Linux (`test:`), Clippy, and MSRV jobs must retain their cache steps.
  3. Run `bash scripts/check-s-3-06-acceptance.sh` — all 6 checks must PASS before opening the PR.
  4. After merging, trigger 5 consecutive CI runs on develop (empty commits or `workflow_dispatch`) and document all 5 run IDs in the investigation doc.
