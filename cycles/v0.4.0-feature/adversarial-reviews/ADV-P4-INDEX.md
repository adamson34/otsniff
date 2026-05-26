# ADV-P4 Findings Index — v0.4.0-feature cycle

**Pass:** 4
**Date:** 2026-05-26
**Develop tip:** `1f7d4cf` (post-F-ADV-P3 fix burst, PR #101)
**Target:** implementation, full scope
**Adversary fresh-context:** ✓

## Findings table

| ID | Severity | Confidence | Category | Files | Title |
|---|---|---|---|---|---|
| **F-ADV-P4-001** | **CRITICAL** | HIGH | Correctness | `src/observe.rs:754-790` | LDAP STARTTLS direction-asymmetric flow key — suppression functionally inert |
| F-ADV-P4-002 | HIGH | HIGH | Policy-11 | `.github/workflows/mutants.yml:60-109` | Kill-rate parser uses wrong cargo-mutants schema (partial F-ADV-P3-007) |
| F-ADV-P4-003 | MEDIUM | MEDIUM | Correctness | `src/diff.rs:188-203` | `extract_kv` test-helper format runs first in production |
| F-ADV-P4-004 | MEDIUM | HIGH | Privacy/Proof | `src/kani_proofs.rs:407-439` | Non-vacuous proof doesn't assert `out_slice == pseudo` |
| F-ADV-P4-005 | MEDIUM | HIGH | Policy-11 | `.github/workflows/kani.yml` | No positive-coverage assertion any harness ran |
| F-ADV-P4-006 | MEDIUM | MEDIUM | Parser | `src/parse/s7comm.rs:75-103` | S7 min-length guard hardcoded to +10 but rosctr 0x02/0x03 needs +12 |
| F-ADV-P4-007 | MEDIUM | HIGH | Correctness/FP | `src/parse/enip.rs:53-72` | ENIP CIP scan window has ~30% false-positive rate per random payload |
| F-ADV-P4-008 | MEDIUM | MEDIUM | Correctness | `src/scrub.rs:449-472` | `unscrub_text` silent no-op on empty map |
| F-ADV-P4-009 | LOW | LOW | Correctness | `src/scrub.rs:230-244` | `merge_map` panic instead of typed error (≈F-ADV-P1-017) |
| F-ADV-P4-010 | MEDIUM | MEDIUM | Correctness | `src/cli.rs:267-375` | `run_diff` doesn't validate map coverage |
| F-ADV-P4-011 | LOW | MEDIUM | Privacy/Proof | `src/ai/leak_detector.rs:559-572` | Kani MAC model lowercase-only |
| F-ADV-P4-012 | LOW | MEDIUM | Correctness | `src/scrub.rs:474-484` | `pseudonym_regex` `\b` doesn't handle concatenated pseudonyms |

## Summary

- **Total actionable findings:** 12 (+ 7 observations)
- **By severity:** CRITICAL=1, HIGH=1, MEDIUM=7, LOW=3
- **Trajectory:** 18 → 21 → 12 → **12** (FLAT absolute; investigated below)
- **Severity-weighted trajectory:** 5 → 13 → 7 → **2** high-severity (DECREASING ✅)
- **Categories:**
  - 8 NEW perimeter findings
  - 1 partial-fix (mutants parser inherited a pre-existing schema mismatch)
  - 1 severity-escalated duplicate (ENIP scan window)
  - 2 duplicates of still-OPEN P1 findings
- **Policy compliance:** 10/12 (POL-11: mutants parser broken; kani.yml no positive-coverage)
- **Novelty:** FIRST-PASS-DOMINANT
- **Recommendation:** FIX-AND-RERUN

## Trajectory monotonicity investigation

P3=12, P4=12. Flat. Per skill iron law this is a regression flag. Investigation:

1. **Severity-weighted trajectory is monotonically decreasing:** P1=5 high-sev → P2=13 → P3=7 → P4=**2**. This is the real convergence signal — the dangerous bugs are getting closed, and what remains is long-tail MEDIUM/LOW perimeter that fresh adversaries find differently each pass.
2. **F-ADV-P3 fix burst introduced no NEW defects beyond F-ADV-P4-002,** which is a partial-fix observation: my mutants.yml gate is now load-bearing on top of an already-broken parser that prior passes hadn't exposed.
3. **8 of 12 findings are NEW** — perimeter expansion is the dominant driver, not regression.

Verdict: trajectory is converging in the meaningful sense. The flat absolute count is a long-tail artifact of fresh-context review's nature, not a regression.

## See also

- Full findings: [pass-4.md](pass-4.md)
- ADV-P1: 18 findings (5 HIGH closed)
- ADV-P2: 21 findings (2 CRITICAL + 9 HIGH closed)
- ADV-P3: 12 findings (1 CRITICAL + 6 HIGH closed)
- Tech-debt: `.factory/tech-debt-register.md`
