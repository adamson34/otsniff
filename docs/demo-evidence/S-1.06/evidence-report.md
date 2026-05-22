---
story_id: S-1.06
cycle: v0.4.0-feature
recorded: 2026-05-12T00:00
recorder: vsdd-factory:demo-recorder
artifact_type: structural-evidence
---

# Demo Evidence — S-1.06 ADR backfill

This is a docs-only story (`tdd_mode: facade`). Evidence is the
presence and content of the 5 new ADR files plus the ARCH-INDEX
status update. No runtime artifacts apply.

## AC-001 — ADR-0008 (no async runtime)

- File: [docs/adr/0008-sync-no-async-runtime.md](../../adr/0008-sync-no-async-runtime.md)
- Lines: 88
- Citations present: Tokio absent from Cargo.toml; single-binary distribution; single-pass pipeline.
- Citation grep: PASS (`grep -l "Tokio"` returned the file)

## AC-002 — ADR-0009 (logical flow key)

- File: [docs/adr/0009-logical-flow-key.md](../../adr/0009-logical-flow-key.md)
- Lines: 101
- Citations present: SPAN src_port noise; observe.rs BTreeMap for deterministic flow grouping.
- Citation grep: PASS (`grep -l "src_port"` returned the file)

## AC-003 — ADR-0010 (cred finding rollup)

- File: [docs/adr/0010-cred-finding-rollup-by-kind.md](../../adr/0010-cred-finding-rollup-by-kind.md)
- Lines: 95
- Citations present: 4SICS-22 corpus trigger; P0-1 priority classification.
- Citation grep: PASS (`grep -lE "4SICS|P0-1"` returned the file)

## AC-004 — ADR-0011 (pulldown-cmark raw-HTML filter)

- File: [docs/adr/0011-pulldown-cmark-with-raw-html-filter.md](../../adr/0011-pulldown-cmark-with-raw-html-filter.md)
- Lines: 126
- Citations present: pulldown-cmark crate; XSS sentinel test in snapshot suite.
- Citation grep: PASS (`grep -lE "pulldown-cmark|sentinel"` returned the file)

## AC-005 — ADR-0012 (audit log auto-derives path)

- File: [docs/adr/0012-audit-log-auto-derives-path.md](../../adr/0012-audit-log-auto-derives-path.md)
- Lines: 140
- Citations present: `<report-stem>.audit.json` path convention; `audit.json` suffix.
- Citation grep: PASS (`grep -lE "audit.json|report-stem"` returned the file)

## AC-006 — ARCH-INDEX updated

- File: `.factory/specs/architecture/ARCH-INDEX.md` (on factory-artifacts branch, commit 6fe07a3)
- ADR catalog table now has 12 "Accepted" rows (ADR-0001 through ADR-0012).
- The "proposed but not written" subsection was removed.
- Cross-reference: `grep -c "Accepted" .factory/specs/architecture/ARCH-INDEX.md` returns 12.
- Note: This file lives on the `factory-artifacts` branch and is not present in this feature branch worktree; verified via the commit reference above.
