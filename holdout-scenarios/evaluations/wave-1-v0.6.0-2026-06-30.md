---
document_type: holdout-evaluation
project: otsniff
cycle: v0.6.0-feature
wave: 1
level: ops
version: "1.0"
status: complete
producer: holdout-evaluator (information-asymmetric, black-box)
timestamp: 2026-06-30T00:00:00Z
develop_tip: 6334e36
stories_evaluated: ["S-8.01"]
---

# Wave-1 Holdout Evaluation — v0.6.0-feature

## Scenarios run

| Scenario | Focus | Verdict | Score |
|---|---|---|---|
| HS-003 (privacy invariant survives new extractor surfaces) | S-8.01 adds mDNS/NetBIOS-NS/LLMNR hostname extractors — verify none leak to the AI-bound/scrubbed output | **PASS** | **1.00 / 1.00** |

HS-003 is the directly-relevant scenario for this wave: it was authored to guard the
privacy invariant against *new* extractor surfaces, and S-8.01 introduces three.
Other wave-1 scenarios (HS-009 progress no-leak, HS-008 diff pseudonyms) are not
exercised by S-8.01 and were not re-run.

## HS-003 evidence (black-box, built binary on develop `6334e36`)

- Probe: `docs/demo-evidence/S-8.01/fixtures/hostname-extraction.pcap` (known hostnames `HMI-LINE-3` mDNS, `PLC-LINE3` NetBIOS-NS, `ENG-WS-01` LLMNR).
- Functional baseline: all three appear as asset labels in the JSON inventory.
- Privacy invariant on `scrubbed.md` (the AI-safe artifact): 0 raw hostnames, 0 real IPv4 (`192.168.10.5/.10/.20`), 0 MACs; IPv4-shaped token count 0; MAC-shaped token count 0.
- Pseudonymization proof: `map.json` maps the three hostnames to `name_001/002/003`, and those pseudonyms appear in `scrubbed.md` — substituted, not dropped.
- Performance: scrub 0.072s (< 1s budget).

## Wave-1 gate summary

| Gate dimension | Result | Source |
|---|---|---|
| Full test suite on merged develop | PASS (514 tests, 0 fail) | orchestrator re-run on develop `6334e36` |
| Adversary (story diff) | CONVERGED (6 passes) | per-story Step 4.5; `cycles/v0.6.0-feature/S-8.01/adversary-convergence-state.json` |
| Code review (fresh-eyes PR) | done | pr-manager pr-reviewer step (PR #138) |
| Security review | done (parser panic/DoS + injection surface) | pr-manager security step (PR #138) |
| Consistency (BC↔code↔story, RULES.md) | PASS | adversary pass 6 anchoring audit + CI rule-catalog drift test |
| Holdout | PASS (HS-003, 1.00) | this evaluation |
| Demo evidence | PASS | `docs/demo-evidence/S-8.01/` |

**WAVE-1 GATE: PASSED.** v0.6.0-feature wave 1 (S-8.01) complete; cycle ready for the next story.
