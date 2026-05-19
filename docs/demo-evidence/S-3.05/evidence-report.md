# Demo Evidence Report — S-3.05

| Field | Value |
|-------|-------|
| Story ID | S-3.05 |
| Behavioral Contract | BC-build.001 (informal — not yet in BC-INDEX) |
| Worktree HEAD SHA | e11a5d5e2748e657bdf51a9eaf5d4c4a98e972ac |
| Evidence date | 2026-05-19 |

## Coverage Table

| AC | Description | Result |
|----|-------------|--------|
| AC-001 | Coverage job in `.github/workflows/ci.yml` (cargo-llvm-cov + codecov-action@v4, ubuntu-latest) | PASS |
| AC-002 | Tokenless upload — no `token:` input on codecov action step | PASS |
| AC-003 | `codecov.yml` present with project/patch targets and ignore list | PASS |
| AC-004 | README badge pointing to `codecov.io/gh/adamson34/otsniff` in badge row | PASS |
| AC-005 | All 7 pre-existing CI job keys (fmt, clippy, test, test-macos, msrv, no-user-paths, deny) untouched | PASS |
| AC-006 | Badge URL resolves to real coverage % post-merge | DEFERRED-post-merge |

Acceptance script result: **6/6 checks passed, 0 failed, 1 skipped** (AC-006 skipped by design).

## Non-standard pattern note

Facade-mode CI/docs story — evidence is captured shell command output, not VHS
recordings or Playwright specs. The deliverables are YAML, config, and docs
changes with no Rust source modifications; interactive recordings would add no
signal beyond what the structural `grep`/`awk` checks already demonstrate.
