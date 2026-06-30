---
document_type: holdout-evaluation
project: otsniff
cycle: v0.6.0-feature
wave: 5
level: ops
version: "1.0"
status: complete
producer: holdout-evaluator (information-asymmetric, black-box)
timestamp: 2026-06-30T00:00:00Z
develop_tip: 5525b5c
stories_evaluated: ["S-12.01"]
---

# Wave-5 Holdout Evaluation — v0.6.0-feature

## Scenarios run

| Scenario | Focus | Verdict | Score |
|---|---|---|---|
| HS-013 (MITRE ATT&CK for ICS coverage + per-finding surfacing) | S-12.01 — every detection rule mapped; per-finding techniques in HTML/MD/JSON | **PASS** | **1.00 / 1.00** |

## HS-013 evidence (black-box, release binary on develop `5525b5c`)

Capture: `tests/fixtures/synthetic-1mb.pcap` (fires `ics.modbus_writes`, a
multi-technique mapped finding).

| Check | Verdict | Evidence |
|---|---|---|
| 1 — catalog coverage | PASS | `otsniff rules --format json`: 23 rules; all 20 non-zonewarden carry a `MitreIcsAttack` ref; the 3 `zonewarden.*` correctly exempt. The 7 historically-unmapped rules now mapped (creds→T0859, smbv1→T0866, TLS→T0830, dns/ntp→T0884) |
| 2 — IDs real / URLs live | PASS | 12 distinct IDs; every label id matches its URL id; `curl -L` all 12 → HTTP 200, zero 404s |
| 3 — HTML surfacing | PASS | finding card has `<a href="https://attack.mitre.org/techniques/T0836/">T0836 — Modify Parameter</a>` (+ T0855) |
| 4 — MD surfacing | PASS | `**MITRE ATT&CK for ICS.** [T0836 — …](…), [T0855 — …](…)` |
| 5 — JSON surfacing | PASS | finding's `mitre_techniques` array non-empty, each with `label` + `url` |
| 6 — no regression | PASS | exit 0; Summary/Findings/Asset inventory/Top flows intact; sub-second |

Satisfaction 1.00 (functional 0.60 + edge 0.30 + perf 0.10). Note: the fixture
fires one (multi-technique) finding; catalog coverage validates all 23 rules
regardless, so surfacing is fully exercised in all three formats.

## Wave-5 gate summary

| Gate dimension | Result | Source |
|---|---|---|
| Full test suite on merged develop | PASS (669 tests, 0 fail) | orchestrator re-run on develop `5525b5c` |
| Per-story adversarial review | CONVERGED (3 passes, pass-1 zero findings) | `cycles/v0.6.0-feature/S-12.01/adversary-convergence-state.json` |
| Holdout HS-013 | PASS (1.00) | this evaluation |
| Demo evidence | present (per-finding + coverage VHS) | `docs/demo-evidence/S-12.01/` |
| Consistency (BC/STORY index anchoring) | PASS | BC-INDEX 117, STORY-INDEX 45 stories / 12 epics |

**Wave-5 gate: PASSED.**
