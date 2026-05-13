---
story_id: S-2.12
cycle: v0.4.1-patch
recorded: 2026-05-13T13:01
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-2.12 recon.port_scan rollup by source IP

Rolls up recon detection by scanning source instead of per
`(src, port, proto)` tuple. Real-PCAP cardinality reduction:
26,067 → 23 findings on the 4SICS-GeekLounge-151022 capture.

## AC-001..003, AC-005..006 — Rollup + classification + thresholds

Evidence: ![tests](AC-001-rollup-tests.gif)
+ [AC-001-007-tests.txt](AC-001-007-tests.txt)

All 11 recon_port_scan tests pass (9 new/updated + 2 retained):
- `recon_port_scan_rolls_up_by_source_not_per_port` — AC-001 primary grouping
- `recon_port_scan_evidence_summarizes_scan_pattern` — AC-002 evidence rows
- `recon_port_scan_classifies_horizontal_vertical_combined` — AC-003/AC-006
- `recon_port_scan_skips_broadcast_dst` — AC-003 broadcast suppression
- `recon_port_scan_silent_below_threshold` — threshold gate
- `recon_port_scan_below_both_thresholds_silent` — both-threshold gate
- `recon_port_scan_two_scanners_two_findings` — two-source separation
- `recon_port_scan_fires_at_threshold` — AC-006 updated S-2.10 test
- `recon_port_scan_escalates_at_high_threshold` — High severity at 50 dsts
- `recon_port_scan_severity_high_at_50_dsts` — severity escalation
- `recon_port_scan_4sics_22_caps_at_20_findings` — AC-004 fixture-gated

## AC-004 — 4SICS-22 regression

Evidence: [AC-004-4sics-22-regression.txt](AC-004-4sics-22-regression.txt)

Real-capture verification: detector emits 23 findings (down from 26,067)
on a 200 MB, 2.25M-packet, 99-host capture with known scanners.
1,135x reduction confirms rollup-by-source is working correctly.

## AC-007 — demo.gif refresh

`media/demo.gif` re-recorded against the post-S-2.12 detector +
post-brand HTML template using the 4SICS-GeekLounge-151020 capture
(25 MB, clean canvas). The tape file `media/demo.tape` enforces a
minimal PS1 and runs from `media/` so gif frames contain no
home-directory paths. POL-12 lint confirms no absolute paths in tape.

Previous size: 300 KB. New size: 348 KB (within acceptable range, well under 2 MB).
