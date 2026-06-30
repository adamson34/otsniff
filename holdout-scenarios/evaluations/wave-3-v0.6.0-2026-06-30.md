---
document_type: holdout-evaluation
project: otsniff
cycle: v0.6.0-feature
wave: 3
level: ops
version: "1.0"
status: complete
producer: holdout-evaluator (information-asymmetric, black-box)
timestamp: 2026-06-30T00:00:00Z
develop_tip: 668d704
stories_evaluated: ["S-10.01"]
---

# Wave-3 Holdout Evaluation — v0.6.0-feature

## Scenarios run

| Scenario | Focus | Verdict | Score |
|---|---|---|---|
| HS-011 (capture-sanity warning fires on degenerate timestamps, silent on sane) | S-10.01 — verify each degenerate class warns on stderr + report banner, and a sane capture is silent + unchanged | **PASS** | **1.00 / 1.00** |

## HS-011 evidence (black-box, release binary on develop `668d704`)

Fixtures (stdlib generator `docs/demo-evidence/S-10.01/fixtures/make_pcaps.py`):
`epoch.pcap` (all ts 0), `subsec.pcap` (~0.2s span), `nonmono.pcap` (2nd packet
60s earlier), `sane.pcap` (BASE/+5/+12 ascending).

| Check | Verdict | Evidence |
|---|---|---|
| 1 — epoch warning | PASS | stderr `WARNING: ...all at/before the Unix epoch...`; HTML+MD banner present; "Capture window: 1970… → 1970…" still renders |
| 2 — sub-second warning | PASS | stderr `WARNING: capture spans less than one second...`; banner present |
| 3 — non-monotonic warning | PASS | stderr `WARNING: ...not monotonically increasing...`; banner present; window shows the inverted range |
| 4 — sane is silent + unchanged | PASS | stderr only `wrote ...`; `capture-warning`/`timestamp warning` count 0 in HTML+MD; normal readable report |
| 5 — no panic / clean exit | PASS | all four exit 0, each writes a `</html>`-terminated report |

Performance: each run < 0.1s. Satisfaction 1.00 (functional 0.60 + edge 0.30 + perf 0.10).

## Wave-3 gate summary

| Gate dimension | Result | Source |
|---|---|---|
| Full test suite on merged develop | PASS (659 tests, 0 fail) | orchestrator re-run on develop `668d704` |
| Per-story adversarial review | CONVERGED (3 passes, all clean, novelty LOW) | `cycles/v0.6.0-feature/S-10.01/adversary-convergence-state.json` |
| Holdout HS-011 | PASS (1.00) | this evaluation |
| Demo evidence | present (degenerate vs sane VHS) | `docs/demo-evidence/S-10.01/` |
| Consistency (BC/STORY index anchoring) | PASS | BC-INDEX 113, STORY-INDEX 43 stories / 10 epics |

**Wave-3 gate: PASSED.**
