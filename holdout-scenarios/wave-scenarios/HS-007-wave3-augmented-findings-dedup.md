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
id: "HS-007"
category: "behavioral-subtleties"
must_pass: "true"
priority: "must-pass"
wave: 3
epic_id: "E-5"
behavioral_contracts: ["BC-6.05.003"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-007: AI-augmented findings dedupe against rule findings

> **NOT FOR IMPLEMENTERS.**

## Scenario

After S-5.03 lands, when the rule layer fires a `creds.ftp` finding
for a host and the LLM suggests an augmented finding for the same host
on the same surface, the augmented finding is suppressed (or attached
as a note to the rule finding), not double-reported.

1. **Precondition:** Wave-3 post-merge of S-5.03. A mock provider
   replaces `claude` and returns a deterministic JSON response that
   includes one augmented finding overlapping with a known rule finding,
   plus one novel augmented finding.
2. **Action:** Run `otsniff analyze fixture.pcap -o out.html --ai`.
3. **Expected:**
   - The HTML contains the rule finding for the overlapping host.
   - The HTML does NOT contain a separate "AI-augmented" entry for the
     same host on the same surface — only the novel augmented finding
     remains.
   - The novel augmented finding renders with its confidence + reasoning.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-6.05.003 | dedup against rule findings |

## Evaluation Rubric

- Functional correctness (0.6)
- Edge case handling (0.2): partial-overlap evidence still suppresses
- Other (0.2)

## Failure Guidance

"HOLDOUT LOW: HS-007 (satisfaction: 0.XX) — augmented findings not deduplicated against rule findings"
