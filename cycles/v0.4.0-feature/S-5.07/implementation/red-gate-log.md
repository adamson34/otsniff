---
document_type: red-gate-log
level: ops
version: "1.0"
status: verified
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - tests/snapshot.rs
  - templates/report.html
  - .factory/stories/S-5.07-collapsible-finding-cards.md
traces_to: BC-8.01.005
red_gate_verified: true
---

# Red Gate Log: S-5.07 — Collapsible finding cards

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-5.07 | 5 | Yes | PASSED |

## Stubs Created

None. Template-only change — no Rust API stubs needed. Tests call the
existing `render_html` function against the unmodified template. The
template's `<div class="finding sev-...">` is the failing artifact.

## Red Gate Verification

### S-5.07

- AC-001 (BC-8.01.005): `test_bc_8_01_005_finding_cards_wrap_in_details_open` — FAIL (expected)
  - Assertion: `report.contains("<details open class=\"finding sev-")`
  - Failure: template uses `<div class="finding sev-...">`, not `<details open ...>`

- AC-002 (BC-8.01.005): `test_bc_8_01_005_summary_marker_suppressed` — FAIL (expected)
  - Assertion: `report.contains("details.finding > summary::-webkit-details-marker { display: none")`
  - Failure: CSS rule not yet present in template

- AC-003 (BC-8.01.005): `test_bc_8_01_005_default_state_is_open` — FAIL (expected)
  - Assertion: `report.contains("<details open class=\"finding sev-")`
  - Failure: same root cause as AC-001; guard prevents vacuous pass

- AC-004 (BC-8.01.005): `test_bc_8_01_005_nested_evidence_still_present` — FAIL (expected)
  - Assertion: `report.contains("<details open class=\"finding sev-")`
  - Failure: outer card guard fails first; prevents vacuous pass on the
    nested-details assertions (which would otherwise pass on the old template)

- AC-005 (BC-8.01.005): `test_bc_8_01_005_print_mode_forces_open` — FAIL (expected)
  - Assertion: `report.contains("@media print") && report.contains("details.finding")`
  - Failure: `details.finding` not yet present in the print block

## Failure types

All 5 failures are `assert!` / `assert_eq!` panics — not compile errors,
not runtime panics unrelated to assertions. Tests compile and run cleanly;
they simply observe the current template output.

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 54 pre-existing snapshot tests | all pass |

Command: `cargo test --all-features --test snapshot`
Result: `test result: FAILED. 54 passed; 5 failed; 0 ignored`

## Template inspection note

AC-003 and AC-004 required a guard assertion (`report.contains("<details open
class=\"finding sev-")`) prepended before the real AC assertion. Without this
guard both tests passed vacuously on the current template:

- AC-003: `<details class="finding "` count == 0 was already vacuously true
  because cards are `<div>`s, not `<details>` elements at all.
- AC-004: the nested `<details>` + `<summary>Evidence` and
  `<details open>` + `<summary>Investigation playbook` blocks already exist
  in the template body (for evidence, criteria, playbook sub-sections).

The guard correctly ties each test's pass condition to the structural change
required by the implementer.

## Hand-Off to Implementer

- Story ready for implementation: S-5.07
- Implementation guidance:
  1. In `templates/report.html` line 324, change
     `<div class="finding sev-{{ f.severity_class }}">` to
     `<details open class="finding sev-{{ f.severity_class }}">`
  2. Wrap existing `<h3>...</h3>` heading in `<summary>...</summary>`
  3. Close with `</details>` instead of `</div>` at end of card
  4. Add CSS: `details.finding > summary::-webkit-details-marker { display: none; }`
  5. Add print-mode rules targeting `details.finding` inside `@media print`
  6. Run `cargo insta review` to accept the structural snapshot diff
  7. Verify all 5 new tests pass; verify `render_html_snapshot_remains_data_stable` still passes
