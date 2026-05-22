# Evidence Report: S-3.06

**Story:** S-3.06 — Stop the recurring macOS rustup-init/cargo flake in CI
**Chosen fix:** Option (b'') — drop `Swatinem/rust-cache@v2` from the `test-macos` job only
**Worktree HEAD SHA:** 9bac67638a1b419e5bd9139ee2b7e430b82d5907
**Date captured:** 2026-05-15

---

## Coverage Map

| AC | Description | Evidence file | Status |
|----|-------------|--------------|--------|
| AC-001-a | Investigation note committed | `AC-001-investigation-doc.md` | PASS-pre-merge |
| AC-001-b | Note has 7+ sections (no stub headings) | `AC-001-investigation-doc.md` | PASS-pre-merge |
| AC-001-c | Note contains zero TODOs | `AC-001-investigation-doc.md` | PASS-pre-merge |
| AC-002-pre-merge | `Swatinem/rust-cache@v2` removed from `test-macos` only | `AC-002-workflow-diff.md` | PASS-pre-merge |
| AC-002-post-merge | 5 consecutive macOS CI runs pass without rerun | `AC-002-five-run-plan.md` | DEFERRED-post-merge |
| AC-003 | Rollback plan documented with next fallback | `AC-003-rollback-evidence.md` | PASS-pre-merge |

---

## Limitation

AC-002 has both a pre-merge artifact (workflow YAML diff) and a post-merge artifact
(5 green CI runs). Only the pre-merge artifact is captured here. The post-merge
artifact must be filled in after the PR merges to develop: update `AC-002-five-run-plan.md`
with actual run IDs and conclusions, then update the AC-002-post-merge row above from
`DEFERRED-post-merge` to `PASS` or `FAIL`.

---

## Non-standard recording note

This is a CI-workflow ops story with `tdd_mode: facade`. Standard CLI/browser demo
recording (VHS/Playwright) does not apply — the deliverable is CI workflow behavior,
not a user-facing binary or web interface. Evidence consists of captured terminal
output proving acceptance criteria pass against the committed artifacts (investigation
note, workflow YAML diff) rather than animated terminal recordings.
