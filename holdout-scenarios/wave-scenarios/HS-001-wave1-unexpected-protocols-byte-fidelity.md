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
id: "HS-001"
category: "behavioral-subtleties"
must_pass: "true"
priority: "must-pass"
wave: 1
epic_id: "E-1"
behavioral_contracts: ["BC-3.05.002"]
lifecycle_status: active
introduced: v0.4.0-feature
last_evaluated: null
---

# HS-001: Unexpected-protocols rule fires on every documented label

> **NOT FOR IMPLEMENTERS.** This scenario is held by the evaluator.

## Scenario

1. **Precondition:** otsniff at the post-Wave-1 commit; default OT subnet.
2. **Action:** Run `otsniff analyze <pcap> -o out.html --json out.json`
   on a synthetic PCAP that contains exactly one flow per "no-fly"
   label currently documented in `docs/RULES.md`'s
   `ot.unexpected_protocols` entry.
3. **Expected:** The JSON output contains an `ot.unexpected_protocols`
   finding whose evidence enumerates every documented label exactly
   once. No label is missing. No label appears that is not in the
   documented trigger string.

## Behavioral Contract Linkage

| BC ID | Clause Tested | Scenario Aspect |
|-------|--------------|-----------------|
| BC-3.05.002 | postcondition: trigger string matches actual labels detected | Round-trip from RULES.md → detector → JSON |

## Verification Approach

- Construct fixture: a `Vec<Flow>` containing one flow per port in the
  detector's port-to-label table (use a deterministic
  `Observations` builder, not a real PCAP, to avoid timing variation).
- Run otsniff with `--json` output.
- Parse JSON, locate `ot.unexpected_protocols` finding.
- Extract the set of labels from evidence rows.
- Compare with the labels parsed from `RULES.md`'s trigger string.

## Evaluation Rubric

- Functional correctness (0.5): exact set equality of detected vs documented labels
- Edge case handling (0.2): zero-flow PCAP produces no finding (no false positive)
- Error quality (0.1): N/A
- Performance (0.1): completes within 5 seconds
- Data integrity (0.1): JSON is well-formed, evidence rows sorted deterministically

## Edge Conditions

- A label exists in the detector that is not in the trigger string → FAIL.
- A label is in the trigger string that the detector never fires on → FAIL.
- The detector reports zero findings on the all-labels fixture → FAIL.

## Failure Guidance

Template: "HOLDOUT LOW: HS-001 (satisfaction: 0.XX) — detector ↔ trigger string disagreement on `ot.unexpected_protocols`"
