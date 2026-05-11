---
artifact_type: adversarial-story-review
project: otsniff
pass: 1
reviewer: vsdd-factory:adversary (fresh context, read-only)
verdict: BLOCKING
timestamp: 2026-05-11T22:00:00Z
finding_counts:
  blocking: 7
  substantive: 11
  nitpick: 4
---

# Phase 2 Adversarial Story Review — Pass 1

## Summary

| Severity | Count |
|---|---:|
| BLOCKING | 7 |
| SUBSTANTIVE | 11 |
| NITPICK | 4 |

## Findings

### ADV-P1-001 — Eight stories have `wave:` frontmatter that contradicts STORY-INDEX / wave-schedule / sprint-state
- **Severity:** BLOCKING
- **Location:** S-2.05..2.11 + S-3.02 declare `wave: 2` in frontmatter; STORY-INDEX, wave-schedule, sprint-state all say Wave 1.
- **Issue:** Implementer agents read story frontmatter as the source of truth for scheduling. Eight stories declaring `wave: 2` in frontmatter while index/schedule/sprint state all say Wave 1 produces contradictory dispatch behavior.
- **Recommendation:** Flip the eight frontmatter values to `wave: 1`.

### ADV-P1-002 — Total points arithmetic off by 4; E-2 epic total off by 2
- **Severity:** SUBSTANTIVE
- **Location:** STORY-INDEX claims `Total points: 100` and E-2 = 31; actual sums are 104 and 29.
- **Recommendation:** Correct STORY-INDEX totals.

### ADV-P1-003 — VP-IDs introduced in story frontmatter but defined nowhere
- **Severity:** BLOCKING
- **Location:** S-4.01..04 + S-3.01 declare `verification_properties: ["VP-..."]` but no VP-INDEX exists.
- **Recommendation:** Drop VP-IDs from frontmatter (trace exclusively to BCs) OR create VP-INDEX.md.

### ADV-P1-004 — B.6 source-code drift for `BC-1.02.003` (S7 "password operations") not covered by any story
- **Severity:** BLOCKING
- **Location:** PRD §5 flags S7_METADATA.trigger as requiring source-code fix; no story addresses it.
- **Recommendation:** Add AC to S-1.04 or new story S-1.07 for S7 trigger string fix.

### ADV-P1-005 — S-5.03 references `OtError::AugmentFailed` and S-1.03 references `OtError::AiProvider`, neither exists
- **Severity:** BLOCKING
- **Location:** Both invented variant names; actual variants in src/error.rs are `InputOpen`, `BadInput`, `Parse`, `UnsupportedLinkType`, `WriteOutput`, `Render`, `Json`. Exit code for missing claude is 70 (EX_SOFTWARE), not 1.
- **Recommendation:** Rewrite S-5.03 EC-004 to use real variants; correct S-1.03 to fix the PRD without inventing new variants.

### ADV-P1-006 — S-6.02 references non-existent subsystem "S.10"
- **Severity:** SUBSTANTIVE
- **Recommendation:** Either declare S.10 in ARCH-INDEX or move S-6.02 under S.9.

### ADV-P1-007 — S-1.05 AC-001 grep test is already satisfied today
- **Severity:** SUBSTANTIVE
- **Recommendation:** Replace with positive assertions that BC-S.SS.NNN rows exist and BC-AUDIT alias table renders correctly.

### ADV-P1-008 — Wave-1 file collision risk has no serialization plan
- **Severity:** BLOCKING
- **Location:** 10 stories in Wave 1 edit `src/findings/mod.rs` + `src/rule_catalog.rs`; 7 edit `src/observe.rs`. Wave-schedule asserts MUST-serialize invariant but provides no satisfying plan.
- **Recommendation:** Either chain dependencies in 1-B group OR pre-extract a registration scheme as a Wave-0 prerequisite.

### ADV-P1-009 — S-3.04 lists scrub_text fuzz target but doesn't declare S.5 subsystem
- **Severity:** SUBSTANTIVE
- **Recommendation:** Add S.5 to S-3.04 subsystems list or drop scrub_text harness.

### ADV-P1-010 — S-2.05 AC-003 STARTTLS-suppression test is vacuous
- **Severity:** SUBSTANTIVE
- **Recommendation:** Pair "BindRequest fires" + "BindRequest after STARTTLS doesn't fire" as twin snapshot tests.

### ADV-P1-011 — Story bodies lack a Behavioral Contracts table
- **Severity:** SUBSTANTIVE
- **Recommendation:** Add `## Behavioral Contracts` section to each story (frontmatter alone is brittle).

### ADV-P1-012 — S-1.01 AC-002 disjunctive AC is ambiguous + cap-5 claim is imprecise (per-label, not per-finding)
- **Severity:** SUBSTANTIVE
- **Recommendation:** Pick a direction; clarify the cap is per-label.

### ADV-P1-013 — S-3.02 traces_to/behavioral_contracts inconsistency
- **Severity:** NITPICK
- **Recommendation:** Add BC-AUDIT-013 to traces_to or document the field semantics.

### ADV-P1-014 — S-2.02 EC-003 "saturate at u32::MAX" has no test
- **Severity:** NITPICK
- **Recommendation:** Add AC for saturation OR drop EC-003.

### ADV-P1-015 — S-2.04 EC-004 (fragmented DNP3) defers handling without follow-up story
- **Severity:** SUBSTANTIVE
- **Recommendation:** Either drop EC-004 or open a ROADMAP entry.

### ADV-P1-016 — S-5.03 hardcodes 7-story fan-in but ROADMAP says it's soft
- **Severity:** SUBSTANTIVE
- **Recommendation:** Soften to 3-of-7 detectors as required, others as soft preferences.

### ADV-P1-017 — `tests/snapshot.rs` Wave-1 collision (8+ stories) not in serialization plan
- **Severity:** SUBSTANTIVE
- **Recommendation:** Add to wave-schedule's serialization list OR restructure to one snapshot file per detector.

### ADV-P1-018 — S-4.04 `blocks: []` inconsistent with wave-2 gate criteria
- **Severity:** NITPICK
- **Recommendation:** Either tag S-4.04 as wave-gate OR drop the gate criterion.

### ADV-P1-019 — S-2.03 AC-003 curated-set claim unverifiable
- **Severity:** NITPICK
- **Recommendation:** Specify 15 named vendors to assert against.

### ADV-P1-020 — S-3.01 and S-2.02 assert overlapping memory-bound invariants at different thresholds
- **Severity:** NITPICK
- **Recommendation:** Align thresholds or order-of-dependency.

### ADV-P1-021 — S-1.03 AC-005 IPv6 default direction undecided
- **Severity:** SUBSTANTIVE
- **Recommendation:** Read src/cli.rs first; pre-declare which branch the story documents.

### ADV-P1-022 — STORY-INDEX BC coverage map uses sloppy `BC-1.03.x (cred dedup)` for S-2.02
- **Severity:** NITPICK
- **Recommendation:** Add a new BC for cred_events dedup and trace S-2.02 there.
