---
document_type: red-gate-log
story_id: S-2.12
cycle: v0.4.0-feature  # v0.4.1-patch target after detector rewrite ships
timestamp: 2026-05-13T09:30:00Z
verdict: PASSED
---

# Red Gate Log — S-2.12

## Step 2 — Stub Architect

**Action:** Skipped. S-2.12 is a rewrite of an existing detector
(`src/findings/recon_scan.rs::detect`). No new modules; no stubs.
cargo check clean on baseline.

## Step 3 — Test Writer

**Commit:** `0422895` test(S-2.12): add/update failing tests for
recon.port_scan source-rollup (BC-3.05.006)

**Files:**
- `tests/snapshot.rs` (+487 net): removed `recon_port_scan_separates_by_port`;
  rewrote `fires_at_threshold` / `escalates_at_high_threshold` /
  `silent_below_threshold`; added 6 new fixture builders + 6 new tests
- `tests/cli_smoke.rs` (+41): fixture-gated 4SICS-22 regression
  asserting `recon.port_scan` count ≤ 20

**Tests now failing (9):**
- `recon_port_scan_rolls_up_by_source_not_per_port` — primary AC-001
- `recon_port_scan_classifies_horizontal_vertical_combined` — AC-002
- `recon_port_scan_evidence_summarizes_scan_pattern` — AC-002
- `recon_port_scan_severity_high_at_50_dsts` — AC-001 escalation
- `recon_port_scan_two_scanners_two_findings` — multi-source separation
- `recon_port_scan_below_both_thresholds_silent` — AC-001 negation
- `recon_port_scan_fires_at_threshold` (updated thresholds 5 → 10)
- `recon_port_scan_escalates_at_high_threshold` (updated 25 → 50)
- `recon_port_scan_silent_below_threshold` (updated 4 → 9)

## Red Gate verification (independent)

```
lib:        94 passed; 0 failed
snapshot:   37 passed; 9 failed
cli_smoke:  16 passed; 0 failed  (4SICS-22 test skips when fixture absent in this context; runs in user env)
```

All 9 failures are `assert!` panics against the current
`(src, port, proto)` grouping. POL-12 lint clean (140 files scanned).

## Verdict

**Red Gate PASSED.** Ready for implementer.
