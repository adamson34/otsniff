---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-06-30T00:00:00Z
phase: 2
inputs: [stories/S-11.01-diff-capture-window-normalization.md, behavioral-contracts/BC-INDEX.md]
traces_to: "P1-11"
id: "HS-012"
category: "behavioral-subtleties"
must_pass: "true"
priority: "must-pass"
wave: 4
epic_id: "E-11"
behavioral_contracts: ["BC-3.08.004", "BC-3.08.005"]
lifecycle_status: active
introduced: v0.6.0-feature
---

# HS-012: Diff flow-shift is rate-normalized; duration artifacts suppressed, real shifts kept

> **NOT FOR IMPLEMENTERS.**

Black-box evaluator: judge only from the CLI and its outputs. Build your own
fixtures; do not read `src/`.

## Scenario

`otsniff diff` no longer reports a steady-state flow as a "shift" merely because
the two captures cover different durations, but it still reports a flow whose
*rate* genuinely changed — and it warns when the windows differ materially.

### Setup (build your own fixtures, stdlib only)

You need two captures of the SAME logical flow but different DURATIONS, plus
scrub maps. Adapt `docs/demo-evidence/S-9.01/fixtures/make_pcaps.py` (it writes
record `ts_sec`). Build:

- `base.pcap` — one flow A→B with **N packets** spread over **3600s**
  (timestamps 0, 3600/N, …). 
- `curr_steady.pcap` — the SAME flow A→B with **N/2 packets** over **1800s**
  (same per-second rate, half the bytes, half the duration).
- `curr_realshift.pcap` — the same flow A→B with **N packets** over **1800s**
  (DOUBLE the per-second rate).

Generate scrub maps with `otsniff scrub <pcap> -o /dev/null --map <map>.json`
for each, then merge as the `diff` invocation requires (baseline-map +
current-map). (If map plumbing is awkward, reuse a single capture's map for both
sides where pseudonyms line up, or follow whatever the `diff` help text
prescribes — the point is the rate comparison, not map mechanics.)

### Checks

1. **Duration artifact suppressed (BC-3.08.004).** `diff base.pcap curr_steady.pcap`
   (with `--baseline-map`/`--current-map`, `--json out.json`): the flow A→B does
   NOT appear as a flow-shift (its rate ratio ≈ 1.0, below the 2× default).
   Under the OLD raw-byte behavior it would have (byte ratio ≈ 2.0).

2. **Real rate shift preserved (BC-3.08.004).** `diff base.pcap curr_realshift.pcap`:
   the flow A→B IS reported as a flow-shift (rate ratio ≈ 2.0 ≥ default).

3. **Window-mismatch warning (BC-3.08.005).** Both diffs above involve a 3600s vs
   1800s window (2× difference at the boundary; make one side e.g. 1500s so it is
   clearly > 2×): stderr contains a `WARNING:` about the capture windows
   differing, and the diff HTML/MD report carries a window-mismatch banner stating
   whether ratios are rate-normalized.

4. **Degenerate-window fallback (BC-3.08.004/005).** Diff a normal capture against
   one with all-epoch or sub-second timestamps: the run still completes (exit 0),
   the diff falls back to raw byte ratios, and stderr + banner warn that the
   window is degenerate / results may be duration artifacts.

5. **Comparable windows are quiet.** Diff two captures of ~equal duration (within
   2×): NO window-mismatch warning and NO banner; flow-shift detection behaves
   normally on rates.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-3.08.004 | rate-normalized flow-shift ratio; duration artifact suppressed; real shift kept; degenerate fallback |
| BC-3.08.005 | stderr WARNING + report banner on window mismatch / degenerate window; quiet when comparable |

## Verification Approach

- Parse `out.json` (or grep HTML/MD) for the presence/absence of the A→B flow in
  the flow-shifts section across checks 1–2.
- Capture stderr separately; grep for the window-mismatch WARNING (checks 3–5).
- Grep the report files for the banner text (checks 3–5).

## Evaluation Rubric

- Functional correctness (0.6): artifact suppressed (1) AND real shift preserved (2).
- Edge case handling (0.3): window-mismatch warning (3) + degenerate fallback (4) + quiet-when-comparable (5).
- Performance (0.1): diffs complete quickly on tiny fixtures.

## Failure Guidance

"HOLDOUT LOW: HS-012 (satisfaction: 0.XX) — diff flow-shift was not
rate-normalized (duration artifact still flagged or real shift dropped), or the
window-mismatch warning/banner was missing or fired on comparable windows."
