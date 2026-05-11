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
id: "HS-004"
category: "ci-integration"
must_pass: "true"
priority: "must-pass"
wave: 1
epic_id: "E-1"
behavioral_contracts: []
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-004: Spec hygiene leaves no broken BC reference

> **NOT FOR IMPLEMENTERS.**

## Scenario

After E-1 stories merge (S-1.01..1.06), no documentation artifact
references a BC-AUDIT ID that no longer exists in BC-INDEX, and every
BC-AUDIT ID in BC-INDEX has a row in the L-P1-001 BC promotion table
introduced by S-1.05.

1. **Precondition:** Wave-2 post-merge of S-1.05.
2. **Action:** Grep across `.factory/` and `docs/` for `BC-AUDIT-\d{3}`.
3. **Expected:** Every match is either:
   - A row in BC-INDEX, OR
   - A row in the "Legacy audit-IDs" alias table introduced by S-1.05.
   No match is to an orphan ID.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| (cross-artifact integrity) | n/a — structural |

## Verification Approach

- `grep -REn 'BC-AUDIT-[0-9]+' .factory/ docs/` → list of references.
- Parse BC-INDEX for all defined IDs and aliases.
- Compute symmetric difference; assert empty.

## Failure Guidance

"HOLDOUT LOW: HS-004 (satisfaction: 0.XX) — BC-AUDIT references leak after E-1 cleanup"
