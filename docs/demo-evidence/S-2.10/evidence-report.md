---
story_id: S-2.10
cycle: v0.4.0-feature
recorded: 2026-05-12T13:50
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-2.10 recon.port_scan

Adds a new "recon" finding family to otsniff. `recon.port_scan` fires
when a single source IP talks to >= 5 distinct destination IPs on the
same (port, protocol) within the capture window. Severity escalates
from Medium (>= 5) to High (>= 25 distinct destinations). Broadcast and
multicast destinations are skipped.

## AC-001 — Detector fires at threshold + escalates at high count

Evidence: ![detector tests](AC-001-detector-tests.gif)

Five snapshot tests cover:
- `recon_port_scan_fires_at_threshold` — 5 dsts -> Medium finding
- `recon_port_scan_escalates_at_high_threshold` — 25+ dsts -> High severity
- `recon_port_scan_silent_below_threshold` — 4 dsts -> no finding
- `recon_port_scan_skips_broadcast_dst` — broadcast/multicast dsts -> no finding
- `recon_port_scan_separates_by_port` — 5 dsts x 2 ports -> 2 separate findings

## AC-002 — RULES.md updated

Evidence: [rules-catalog.txt](AC-001-rules-catalog.txt)

The auto-generated rule catalog at `docs/RULES.md` now lists
`recon.port_scan` alongside the other finding families. The
`rule_catalog_matches_committed_rules_md` snapshot test stays green.
