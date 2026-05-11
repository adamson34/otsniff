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
id: "HS-009"
category: "edge-case-combinations"
must_pass: "true"
priority: "should-pass"
wave: 1
epic_id: "E-5"
behavioral_contracts: ["BC-9.04.001", "BC-6.04.001"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-009: Progress + heartbeat output never contains real identifiers

> **NOT FOR IMPLEMENTERS.**

## Scenario

The new `-v` parse-loop progress emitter (S-5.01) and the claude
heartbeat (S-5.02) emit only generic progress strings. They never
include host IPs, MACs, hostnames, or any pseudonym map content.

1. **Precondition:** Wave-1 post-merge of S-5.01 and S-5.02.
2. **Action:** `otsniff analyze fixture.pcap -v -o out.html --ai 2> stderr.log`.
3. **Expected:** Every line in `stderr.log` matches one of these patterns:
   - `[parse] processed \d+ packets / \d+(\.\d+)? (KB|MB|GB) ...`
   - `[ai] invoking claude (model: \w+)...`
   - `[ai] \[\d+s\] still working...`
   - `[ai] done in \d+(\.\d+)?s, \d+ bytes response`
   - Standard final-summary lines (existing in v0.3)
   No `stderr.log` line contains an IPv4-shaped, IPv6-shaped, MAC-shaped,
   or hostname-shaped substring.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-9.04.001 | parse-progress emission shape |
| BC-6.04.001 | claude heartbeat shape |

## Evaluation Rubric

- Functional correctness (0.5): all stderr lines match allowed shapes
- Edge case handling (0.3): leak check on stderr passes
- Other (0.2)

## Failure Guidance

"HOLDOUT LOW: HS-009 (satisfaction: 0.XX) — progress/heartbeat output included a real identifier"
