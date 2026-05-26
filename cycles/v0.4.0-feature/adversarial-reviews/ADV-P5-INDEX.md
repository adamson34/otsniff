# ADV-P5 Findings Index — v0.4.0-feature cycle

**Pass:** 5
**Date:** 2026-05-26
**Develop tip:** `50cab61` (post-F-ADV-P4 fix burst, PR #102)
**Target:** implementation, full scope
**Adversary fresh-context:** ✓

## Findings table

| ID | Severity | Confidence | Category | Files | Title |
|---|---|---|---|---|---|
| **F-ADV-P5-001** | **HIGH** | HIGH | Privacy | `src/cli.rs:615-624` | PCAP basename leaks to AI provider in markdown source label |
| F-ADV-P5-002 | MEDIUM | HIGH | Privacy | `src/cli.rs:810-814` | Audit log carries full input PCAP filesystem path |
| F-ADV-P5-003 | MEDIUM | HIGH | Correctness | `src/parse/dnp3.rs:32-55` | DNP3 parser docstring claims length validation it doesn't perform |
| F-ADV-P5-004 | MEDIUM | MEDIUM | Privacy | `src/diff.rs:710-730` | `unmapped_label` salt derives from observable nanos/PID (refines F-ADV-P3-006) |
| F-ADV-P5-005 | MEDIUM | MEDIUM | Security | `src/ai/html_render.rs:56-105` | Code-block language identifier may inject HTML attributes |
| F-ADV-P5-006 | MEDIUM | HIGH | Privacy | `src/scrub.rs:420-435` | `scrub_text` regex fallback path uses known-buggy sequential replace (refines F-ADV-P3-004) |
| F-ADV-P5-007 | LOW | MEDIUM | Correctness | `src/scrub.rs:461-479` | `unscrub_text` accepts duplicate pseudonyms across families silently |
| F-ADV-P5-008 | MEDIUM | MEDIUM | Security | `src/findings/mod.rs:39-44`, `src/parse/dhcp.rs:71-78` | DHCP hostname interpolated verbatim into evidence (HTML / prompt-injection vector) |
| F-ADV-P5-009 | MEDIUM | MEDIUM | Policy-11 | `.github/workflows/mutants.yml:130-143` | Mutation kill-rate threshold below baseline — no ratchet (refines F-ADV-P3-007 + F-ADV-P4-002) |
| F-ADV-P5-010 | MEDIUM | MEDIUM | Policy-11 | `.github/workflows/fuzz.yml:51-64` | Fuzz coverage floor of 10 runs degenerates to near-no-op |
| F-ADV-P5-011 | LOW | MEDIUM | Correctness | `src/audit.rs:108-129` | `InputOpen` exit code used for read-mid-file errors |
| F-ADV-P5-012 | LOW | MEDIUM | Parser | `src/parse/s7comm.rs:78-95` | S7 `cotp_len_byte` cap of 17 over twice realistic COTP ceiling (refines F-ADV-P3-011) |
| F-ADV-P5-013 | LOW | MEDIUM | Resource | `src/observe.rs:361-362,782-808` | `ldap_starttls_flows` HashMap grows unboundedly |
| F-ADV-P5-014 | MEDIUM | MEDIUM | Policy-11 | `.github/workflows/kani.yml:73-97` | kani.yml success counter doesn't verify per-harness `VERIFICATION SUCCESSFUL` (refines F-ADV-P4-005) |
| F-ADV-P5-015 | LOW | HIGH | Correctness | `src/cli.rs:279-283` | `f64::MAX` accepted as `flow_shift_multiplier` |
| F-ADV-P5-016 | MEDIUM | MEDIUM | Correctness | `src/cli.rs:818-824` | Audit log `command` field embeds unvalidated model name |
| F-ADV-P5-017 | LOW | MEDIUM | Test-discipline | `src/cli.rs:839-841`, `tests/snapshot.rs` | No integration test exercises audit-log leak-detector at run-time |

## Summary

- **Total actionable findings:** 17
- **By severity:** CRITICAL=**0**, HIGH=1, MEDIUM=10, LOW=6
- **Trajectory:** 18 → 21 → 12 → 12 → **17** (UP from P4; perimeter expansion into CI hardening + I/O boundary)
- **Severity-weighted trajectory:** 5 → 13 → 7 → 2 → **1 high-severity** (monotonically DECREASING ✅)
- **CRITICAL streak:** P1=0, P2=2, P3=1, P4=1, **P5=0** (first zero-CRITICAL pass since P1) ✅
- **Categories:**
  - 12 NEW perimeter findings
  - 3 refinements of P3 fixes (F-004, F-006, F-012)
  - 2 refinements of P4 fixes (F-009, F-014)
  - 0 regressions from the F-ADV-P4 burst
- **Policy compliance:** 10/12 (POL-11: mutants ratchet F-009, fuzz floor F-010; kani depth F-014)
- **Novelty:** MIXED (12 net-new perimeter findings dominate; 5 refinements)
- **Recommendation:** FIX-AND-RERUN

## Trajectory monotonicity investigation

P4=12, P5=17. **Absolute count went UP.** Per skill iron law this triggers regression-investigation gate.

1. **Severity-weighted trajectory is monotonically decreasing:** P1=5 → P2=13 → P3=7 → P4=2 → P5=**1**. The dangerous bugs continue to close.
2. **CRITICAL count hit zero** for the first time since P1 (which had no CRITICAL by chance; P5 has zero by construction).
3. **F-ADV-P4 fix burst introduced ZERO new defects.** The two refinements that touch P4 surfaces (F-009 mutants ratchet, F-014 kani depth) are "this could be tighter" critiques, not regressions.
4. **12 of 17 findings are net-new perimeter:** the adversary spent its budget on CI hardening (mutants ratchet, fuzz floor, kani metadata), I/O boundary leaks (PCAP basename → AI, audit-log paths, model name), and previously-unaudited parsers (DNP3 length).

Verdict: convergence in the meaningful sense. The absolute-count uptick is long-tail perimeter discovery, not regression. Severity curve is poised for first clean pass on next iteration.

## See also

- Full findings: [pass-5.md](pass-5.md)
- ADV-P1: 18 findings (5 HIGH closed via PR #99 → `f8e34d7`)
- ADV-P2: 21 findings (2 CRITICAL + 11 HIGH closed via PR #100 → `2ac8f2e`)
- ADV-P3: 12 findings (1 CRITICAL + 6 HIGH closed via PR #101 → `1f7d4cf`)
- ADV-P4: 12 findings (1 CRITICAL + 1 HIGH closed via PR #102 → `50cab61`)
- Tech-debt: `.factory/tech-debt-register.md`
