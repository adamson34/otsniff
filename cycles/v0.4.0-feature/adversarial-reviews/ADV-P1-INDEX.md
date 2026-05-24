# ADV-P1 Findings Index — v0.4.0-feature cycle

**Pass:** 1 (first pass)
**Date:** 2026-05-23
**Develop tip:** 7c98a3a
**Target:** implementation, full scope
**Adversary fresh-context status:** ✓ — no prior reviews, tech-debt register, or red-gate logs read

## Findings table

| ID | Severity | Confidence | Category | Files | Title |
|---|---|---|---|---|---|
| F-ADV-P1-001 | HIGH | HIGH | Correctness | `src/cli.rs:92,266,289` | `otsniff diff` ignores user OT subnet config |
| F-ADV-P1-002 | HIGH | HIGH | Correctness | `src/cli.rs:312`, `src/diff.rs:538` | `flow_shift_multiplier` is silently no-op below 2.0 |
| F-ADV-P1-003 | HIGH | HIGH | Correctness/Privacy | `src/findings/ldap_creds.rs:93`, `src/diff.rs:166` | LDAP creds Unicode `→` defeats diff extractors |
| F-ADV-P1-004 | HIGH | HIGH | Test/Privacy | `fuzz/fuzz_targets/scrub_text.rs:13` | scrub_text fuzz uses empty map; substitution never fuzzed |
| F-ADV-P1-005 | HIGH | HIGH | Privacy/Test | `src/kani_proofs.rs:253` | Composed Kani proof is tautological |
| F-ADV-P1-006 | MEDIUM | HIGH | Privacy | `src/cli.rs:849` | `unscrub` has no leak check on AI's response |
| F-ADV-P1-007 | MEDIUM | HIGH | Privacy/Policy | `src/cli.rs:258-352` | Diff output skips `ensure_clean` post-render |
| F-ADV-P1-008 | MEDIUM | MEDIUM | Correctness | `src/diff.rs:309` | Disjoint-maps warning fires on legitimate first-runs |
| F-ADV-P1-009 | MEDIUM | MEDIUM | Privacy | `src/scrub.rs:307` | scrub_text vulnerable to overlapping real values |
| F-ADV-P1-010 | MEDIUM | MEDIUM | Policy-11 | `.github/workflows/kani.yml:18` | kani.yml lacks positive-coverage assertion |
| F-ADV-P1-011 | MEDIUM | MEDIUM | Policy-11 | `.github/workflows/fuzz.yml:1` | fuzz.yml lacks positive-coverage assertion |
| F-ADV-P1-012 | LOW | MEDIUM | Correctness | `src/findings/recon_scan.rs:194` | Broadcast detector misses subnet-directed broadcast |
| F-ADV-P1-013 | MEDIUM | MEDIUM | Correctness | `src/parse/dnp3.rs:46` | DNP3 parser ignores frame length, fixed offset 12 |
| F-ADV-P1-014 | MEDIUM | HIGH | Security | `src/ai/html_render.rs:77` | `javascript:` URL XSS; test asserts opposite of name |
| F-ADV-P1-015 | LOW | HIGH | Privacy/Policy-12 | `src/cli.rs:730`, `src/audit.rs:46` | audit.path contains user-home directory |
| F-ADV-P1-016 | LOW | MEDIUM | Correctness | `src/pcap.rs:136` | Non-Ethernet2 link types silently dropped |
| F-ADV-P1-017 | MEDIUM | MEDIUM | Correctness | `src/scrub.rs:205` | merge_map panics on corrupted baseline map |
| F-ADV-P1-018 | LOW | MEDIUM | Privacy/Test | `src/diff.rs:623` | scrub_finding skips id+recommendation (safe today, fragile) |

## Summary

- **Total findings:** 18
- **Severity:** CRITICAL=0, HIGH=5, MEDIUM=10, LOW=3
- **HIGH-confidence:** 9 / 18
- **Policy compliance:** 10/12 — POL-11 fails (kani.yml + fuzz.yml), POL-12 has runtime leak (audit-log path)
- **Novelty:** FIRST-PASS (100% new findings — expected for ADV-P1)
- **Recommendation:** FIX-AND-RERUN before declaring wave-2 closed

## See also

- Full findings document: [pass-1.md](pass-1.md)
- Cycle state: [`.factory/STATE.md`](../../STATE.md) (if present)
- Tech-debt register: [`.factory/tech-debt-register.md`](../../tech-debt-register.md)
