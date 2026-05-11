---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-05-11T20:50:00Z
phase: 2
inputs: [stories/, behavioral-contracts/, prd.md]
traces_to: ""
id: "HS-008"
category: "behavioral-subtleties"
must_pass: "true"
priority: "must-pass"
wave: 3
epic_id: "E-6"
behavioral_contracts: ["BC-5.03.001", "BC-3.08.001"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-008: `otsniff diff` reports an unchanged host as unchanged

> **NOT FOR IMPLEMENTERS.**

## Scenario

Two captures of the same network at different times contain the same
host with the same role and same findings. The diff report correctly
identifies this host as unchanged (not "new" and not "gone").

1. **Precondition:** Wave-3 post-merge of S-6.03. Two synthetic PCAPs
   `q1.pcap` and `q2.pcap` constructed deterministically:
   - Both contain a Modbus master at the same MAC + IP.
   - Both produce the same single `ics.modbus_writes` finding against
     the same target PLC.
2. **Action:**
   - `otsniff scrub q1.pcap -o q1.md --map q1.map.json`
   - `otsniff scrub q2.pcap -o q2.md --baseline-map q1.map.json --map q2.map.json`
   - `otsniff diff q1.pcap q2.pcap --baseline-map q1.map.json --current-map q2.map.json -o diff.html`
3. **Expected:**
   - `diff.html` summary banner shows: 0 new findings, 1 recurring,
     0 resolved.
   - 0 hosts new, 0 hosts gone, 1 host unchanged.
   - The same `host_001` pseudonym appears in both q1.map.json and
     q2.map.json for the master.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-5.03.001 | stable pseudonyms across captures |
| BC-3.08.001 | new/gone host categorization |

## Verification Approach

- Inspect both maps; assert pseudonym for the shared real IP is identical.
- Parse diff output; assert summary banner.

## Evaluation Rubric

- Functional correctness (0.7)
- Edge case handling (0.2): adding a hostname-only change (DHCP) should not flip "unchanged" → "new"
- Other (0.1)

## Failure Guidance

"HOLDOUT LOW: HS-008 (satisfaction: 0.XX) — diff incorrectly classified an unchanged host across captures"
