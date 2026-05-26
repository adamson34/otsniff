# ADV-P3 Findings Index — v0.4.0-feature cycle

**Pass:** 3
**Date:** 2026-05-26
**Develop tip:** `2ac8f2e` (post-F-ADV-P2 fix burst, PR #100)
**Target:** implementation, full scope
**Adversary fresh-context:** ✓

## Findings table

| ID | Severity | Confidence | Category | Files | Title |
|---|---|---|---|---|---|
| **F-ADV-P3-001** | **CRITICAL** | HIGH | Privacy | `src/cli.rs:496-506` | `run_scrub` writes to disk WITHOUT leak detector (asymmetric to analyze/diff) |
| F-ADV-P3-002 | HIGH | MEDIUM | Privacy/Correctness | `src/report_md.rs:170-191` | Top-flows table embeds raw IPs unconditionally |
| F-ADV-P3-003 | HIGH | HIGH | Security/XSS | `src/ai/html_render.rs:26-35` | `url_is_unsafe` doesn't strip embedded whitespace — `java\tscript:` bypasses (partial F-ADV-P2-001) |
| F-ADV-P3-004 | HIGH | HIGH | Privacy/Correctness | `src/scrub.rs:332-346` | `scrub_text` substring shadowing when real value is prefix of pseudonym |
| F-ADV-P3-005 | HIGH | HIGH | Privacy/Correctness | `src/scrub.rs:63-104` | `ScrubMap::validate` accepts non-canonical pseudonym shapes |
| F-ADV-P3-006 | HIGH | MEDIUM | Privacy | `src/diff.rs:678-684` | `unmapped_<hash4>` has only 16 bits — brute-forceable (partial F-ADV-P2-002) |
| F-ADV-P3-007 | HIGH | HIGH | Policy-11 | `.github/workflows/mutants.yml:36-94` | `mutants.yml` doesn't fail CI on kill-rate regression |
| F-ADV-P3-008 | MEDIUM | HIGH | Test-discipline | `.github/workflows/kani.yml:1-7` | Kani only on weekly cron + dispatch, not PR |
| F-ADV-P3-009 | MEDIUM | HIGH | Correctness | `src/ai/claude_cli.rs:248-258` | `which_claude` doesn't check executable bit |
| F-ADV-P3-010 | MEDIUM | HIGH | Privacy/Policy-12 | `src/cli.rs:767`, `src/audit.rs:46` | Audit log records full filesystem path (≈F-ADV-P1-015) |
| F-ADV-P3-011 | MEDIUM | MEDIUM | Correctness | `src/parse/s7comm.rs:75-83` | `cotp_len_byte` not bounded — implausible lengths accepted |
| F-ADV-P3-012 | MEDIUM | MEDIUM | Correctness | `src/diff.rs:330-342` | EC-002 warning silenced when either map empty |

## Summary

- **Total findings:** 12 (+ 6 observations)
- **By severity:** CRITICAL=1, HIGH=6, MEDIUM=5, LOW=0
- **HIGH-confidence:** 9 / 12
- **Trajectory:** 18 → 21 → 12 — **DECREASING by 9** (regression check ✅)
- **Categories:**
  - 7 NEW perimeter findings
  - 2 partial-fix observations (F-ADV-P2-001 URL stripping incomplete; F-ADV-P2-002 hash strength insufficient)
  - 3 duplicates of still-OPEN F-ADV-P1 findings
- **Root-cause check:** F-ADV-P2 fix burst introduced ZERO new defects
- **Policy compliance:** 10/12 (POL-11 fails on mutants.yml; POL-12 audit-log runtime leak)
- **Novelty:** MIXED
- **Recommendation:** FIX-AND-RERUN

## Convergence horizon

Per skill iron law: minimum 3 clean passes. P3 is NOT clean. Realistic convergence estimate:
- ADV-P4 after F-ADV-P3-001 + 5 HIGH-confidence HIGH fixes
- ADV-P5 if P4 still has findings
- Tech-debt sweep of accumulated MEDIUM/LOW (13+ entries) can be parallel

## See also

- Full findings: [pass-3.md](pass-3.md)
- ADV-P1 index: [ADV-P1-INDEX.md](ADV-P1-INDEX.md) (18 findings, 5 HIGH closed)
- ADV-P2 index: [ADV-P2-INDEX.md](ADV-P2-INDEX.md) (21 findings, 2 CRITICAL + 9 HIGH closed)
- Tech-debt register: `.factory/tech-debt-register.md`
