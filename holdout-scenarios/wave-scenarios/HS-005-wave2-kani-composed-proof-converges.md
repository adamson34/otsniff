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
id: "HS-005"
category: "security-probes"
must_pass: "true"
priority: "must-pass"
wave: 2
epic_id: "E-4"
behavioral_contracts: ["BC-5.02.003"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-005: Kani composed privacy-invariant proof actually converges

> **NOT FOR IMPLEMENTERS.**

## Scenario

After Wave 2 lands (S-4.01..4.04 merged), running the Kani composed
proof harness on a clean checkout completes without timeout, error, or
unsatisfied-precondition stub.

1. **Precondition:** Wave-2 post-merge of S-4.04. cargo-kani installed
   per the version pinned in CI.
2. **Action:** `cargo kani --harness composed_privacy_invariant` from
   a fresh worktree.
3. **Expected:**
   - Exit code 0.
   - Output contains "VERIFICATION:- SUCCESSFUL" (or kani's equivalent).
   - Runtime < CI budget (target: 60 minutes wall).
   - Bounds N (input length) and K (map size) are documented in
     `docs/proofs/privacy-invariant.md`.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-5.02.003 | composed privacy invariant — bounded but otherwise-universal |

## Verification Approach

- Run cargo-kani in CI runner spec.
- Confirm not gated behind an `unwind` or `cover` hack that makes the
  proof tautological.

## Evaluation Rubric

- Functional correctness (0.6): proof passes
- Edge case handling (0.3): bounds documented + justified
- Performance (0.1): CI budget respected

## Failure Guidance

"HOLDOUT LOW: HS-005 (satisfaction: 0.XX) — Kani composed proof did not converge or was tautological"
