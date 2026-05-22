---
story_id: S-5.06
cycle: v0.4.0-feature
recorded: 2026-05-12T15:50
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-5.06 Brand Handoff Application

Applies the brand handoff from the user's package:
- Real "sniff-trail" mark: hollow ring → 5 packet dots along quadratic Bezier → filled disc (per brand handoff §2 v2 symmetric apex)
- Ink/paper/accent palette: `#15171c` / `#fbfaf6` / `#ff7e35`
- JetBrains Mono for display/UI/data, system sans for body
- Inline favicon (base64 data URL) preserves single-file invariant
- 6 brand SVG variants committed under `media/`
- Legacy `media/otsniff-logo.png` removed
- README updated to reference brand SVG marks

## AC-001 — Brand SVGs committed

Evidence: [brand-assets.txt](brand-assets.txt) — 6 SVGs present, legacy PNG removed.

## AC-002 — Brand palette in :root

Evidence: [structural-checks.txt](structural-checks.txt) — `--ink`, `--paper`, `--accent` tokens present; S-5.05's `--bg-strong` / `--crit-soft` etc. removed.

## AC-003 — JetBrains Mono type system

Evidence: [structural-checks.txt](structural-checks.txt) — `--font-mono`, `--font-sans`, `"JetBrains Mono"` all present.

## AC-004 — Brand header with sniff-trail SVG

Evidence: [structural-checks.txt](structural-checks.txt) + [preview.html](preview.html) — brand-header markup present; SVG in header has exactly 7 circles, 0 polylines, 0 paths.

## AC-005 — Inline favicon

Evidence: [structural-checks.txt](structural-checks.txt) — `<link rel="icon">` with base64 data URL in `<head>`.

## AC-006 — README updated

Evidence: README references SVG marks; `media/otsniff-logo.png` no longer referenced; no forbidden brand-tone words present in body copy.

## AC-007 — Snapshot diffs structural only

Evidence: [AC-001-007-tests.txt](AC-001-007-tests.txt) — `render_html_snapshot_remains_data_stable` continues to pass; no data fields changed.

## Preview

[preview.html](preview.html) — open in browser to inspect rendering.
