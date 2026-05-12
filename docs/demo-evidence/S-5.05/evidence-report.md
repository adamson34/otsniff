---
story_id: S-5.05
cycle: v0.4.0-feature
recorded: 2026-05-12T00:00
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-5.05 Report HTML Visual Polish

This is a visual / CSS-only change to the HTML report. The canonical
visual artifact is `tests/snapshots/snapshot__report_html.snap` which
is deterministically generated from a fixture `Observations`.

## AC-001 — Hero band with inline SVG mark

Evidence: `AC-001-002-006-structural-checks.txt` (header + SVG counts);
`AC-001-007-snapshot-tests.txt` (unit test passes).

## AC-002 — Severity-tinted finding cards

Evidence: `AC-001-002-006-structural-checks.txt` (4 `sev-critical` rule
occurrences + `--crit-soft` token).

## AC-003 — Dark mode (prefers-color-scheme)

Evidence: `AC-001-002-006-structural-checks.txt` (1 `prefers-color-scheme: dark`).

## AC-004 — Print color preservation

Evidence: `AC-001-002-006-structural-checks.txt` (1+ `print-color-adjust: exact`).

## AC-005 — Snapshot stability (data-shape guard)

Evidence: `AC-001-007-snapshot-tests.txt` —
`render_html_snapshot_remains_data_stable` passes both before and after
the redesign, confirming no data fields changed.

## AC-006 — PCB-style logo (amended 2026-05-12)

Evidence: `AC-001-002-006-structural-checks.txt` (1 `<polyline` + 4+ `<circle` in the rendered SVG block).

## AC-007 — Collapsible tables (amended 2026-05-12)

Evidence: 2 `<details open>` blocks wrapping the Asset inventory and
Top flows tables, plus `section-summary` styled headings.

## Preview

[preview.html](preview.html) — extracted from the snapshot fixture.
Open in any browser to inspect the rendering directly.
