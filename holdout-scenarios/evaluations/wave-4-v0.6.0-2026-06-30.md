---
document_type: holdout-evaluation
project: otsniff
cycle: v0.6.0-feature
wave: 4
level: ops
version: "1.0"
status: complete
producer: holdout-evaluator (information-asymmetric, black-box)
timestamp: 2026-06-30T00:00:00Z
develop_tip: ad37626
stories_evaluated: ["S-11.01"]
---

# Wave-4 Holdout Evaluation — v0.6.0-feature

## Scenarios run

| Scenario | Focus | Verdict | Score |
|---|---|---|---|
| HS-012 (diff flow-shift rate-normalized — artifact suppressed, real shift kept) | S-11.01 — verify duration-artifact suppression, real-rate-shift preservation, window-mismatch + degenerate surfacing, quiet-when-comparable | **PASS** | **1.00 / 1.00** |

## HS-012 evidence (black-box, release binary on develop `ad37626`)

One flow `192.168.10.10 → 192.168.10.20:502` over different durations
(generator `docs/demo-evidence/S-11.01/fixtures/make_pcaps.py`); the evaluator
added its own `curr_comparable.pcap` (3600s) and `curr_degenerate.pcap` (0s) for
checks 4–5. Per-capture scrub maps; pseudonyms line up deterministically.

| Check | Verdict | Evidence |
|---|---|---|
| 1 — duration artifact suppressed | PASS | `diff base curr_steady` → `flow_shifts: []` (rate ratio ≈ 1.08, not flagged) despite ~2× raw byte difference |
| 2 — real rate shift preserved | PASS | `diff base curr_realshift` → flagged `ratio 2.167` with **identical raw bytes 48→48** — proves rate-normalized, not byte-based |
| 3 — window-mismatch warning + banner | PASS | stderr `WARNING: capture windows differ 2.2× ... rate-normalized (bytes/sec)`; MD + HTML banners present |
| 4 — degenerate-window fallback | PASS | `diff base curr_degenerate` (0s) → exit 0; stderr `WARNING: a capture window is missing or sub-second; ... raw byte counts`; raw fallback banner |
| 5 — comparable windows quiet | PASS | `diff base curr_comparable` (3900s vs 3600s, < 2×) → no WARNING, only the informational `Capture windows:` line, no mismatch banner |

Performance: each diff ≈ 0.03s. Satisfaction 1.00 (functional 0.60 + edge 0.30 + perf 0.10).

## Wave-4 gate summary

| Gate dimension | Result | Source |
|---|---|---|
| Full test suite on merged develop | PASS (668 tests, 0 fail) | orchestrator re-run on develop `ad37626` |
| Per-story adversarial review | CONVERGED (5 passes, 2 fix rounds then 3 clean) | `cycles/v0.6.0-feature/S-11.01/adversary-convergence-state.json` |
| Holdout HS-012 | PASS (1.00) | this evaluation |
| Demo evidence | present (artifact vs real-shift VHS) | `docs/demo-evidence/S-11.01/` |
| Consistency (BC/STORY index anchoring) | PASS | BC-INDEX 115, STORY-INDEX 44 stories / 11 epics |

**Wave-4 gate: PASSED.**
