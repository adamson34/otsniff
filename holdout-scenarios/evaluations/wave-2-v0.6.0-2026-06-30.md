---
document_type: holdout-evaluation
project: otsniff
cycle: v0.6.0-feature
wave: 2
level: ops
version: "1.0"
status: complete
producer: holdout-evaluator (information-asymmetric, black-box)
timestamp: 2026-06-30T00:00:00Z
develop_tip: 030a279
stories_evaluated: ["S-9.01"]
---

# Wave-2 Holdout Evaluation — v0.6.0-feature

## Scenarios run

| Scenario | Focus | Verdict | Score |
|---|---|---|---|
| HS-010 (multi-PCAP union + link-type guard + per-file audit attribution) | S-9.01 multi-file `analyze` — verify union ingestion, mismatched-link-layer refusal, and per-file basename-only audit descriptors | **PASS** | **0.98 / 1.00** |

HS-010 is the directly-relevant scenario for this wave (authored for S-9.01 /
P0-10). Other scenarios are not exercised by S-9.01 and were not re-run.

## HS-010 evidence (black-box, release binary on develop `030a279`)

Fixtures (stdlib generator `docs/demo-evidence/S-9.01/fixtures/make_pcaps.py`):
`part1.pcap` (Ethernet, hosts .10/.20, ts 1000s), `part2.pcap` (Ethernet, hosts
.30/.40, ts 2000s), `sll.pcap` (LINKTYPE_LINUX_SLL=113). Header linktypes
confirmed (`0x01` / `0x71`).

| Check | Verdict | Evidence |
|---|---|---|
| 1 — union ingestion | PASS | `analyze part1 part2` → 4-host union = exact union of singles; window `00:16:40 → 00:33:20` spans both |
| 2 — CLI-order, not sorted | PASS | reversed order → exit 0, same host union; `input` reflects CLI order |
| 3 — zero-input rejection | PASS | `analyze` (no file) → exit 2, "required arguments were not provided: <PCAP>" |
| 4 — link-layer guard | PASS | `analyze part1 sll` → exit 65, error names both files + types, no report written |
| 5 — per-file audit attribution | PASS | `--ai --audit-log` → `schema_version: 2`, `input_pcaps` 2-element array, basenames only, SHA-256s verified bit-for-bit; directory-qualified inputs confirmed stripped to basenames |
| 6 — single-file parity | PASS | `analyze part1` → exit 0, `input` plain string (not list-wrapped), 2 hosts, normal report sections |

Performance: multi-file run (0.049s) within the sum of single-file runs
(0.103s). Check 5 was evaluable — the local `claude` CLI ran headless.

**Cosmetic blemish (no check failed):** passing files out of chronological
order inverts the displayed capture window (start > end). This is the
documented append/CLI-order semantics (EC-005); recorded as `TD-S901-002`.

## Wave-2 gate summary

| Gate dimension | Result | Source |
|---|---|---|
| Full test suite on merged develop | PASS (644 tests, 0 fail) | orchestrator re-run on develop `030a279` |
| Per-story adversarial review | CONVERGED (4 passes; M-1 major fixed) | `cycles/v0.6.0-feature/S-9.01/adversary-convergence-state.json` |
| Holdout HS-010 | PASS (0.98) | this evaluation |
| Demo evidence | present (union + guard VHS) | `docs/demo-evidence/S-9.01/` |
| Consistency (BC/STORY index anchoring) | PASS | BC-INDEX 111, STORY-INDEX 42 stories / 9 epics |

**Wave-2 gate: PASSED.**
