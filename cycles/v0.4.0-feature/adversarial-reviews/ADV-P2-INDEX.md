# ADV-P2 Findings Index — v0.4.0-feature cycle

**Pass:** 2
**Date:** 2026-05-24
**Develop tip:** `f8e34d7` (post-F-ADV-P1-001..005 fix burst)
**Target:** implementation, full scope
**Adversary fresh-context:** ✓

## Findings table

| ID | Severity | Confidence | Category | Files | Title |
|---|---|---|---|---|---|
| **F-ADV-P2-001** | **CRITICAL** | HIGH | Security/Privacy | `src/ai/html_render.rs:80`, `templates/report.html:419` | `javascript:` URL XSS — re-classification of F-ADV-P1-014 |
| **F-ADV-P2-002** | **CRITICAL** | HIGH | Privacy | `src/cli.rs:267-365`, `src/diff.rs:51,289,514` | Diff has no fail-closed leak detector — re-classification of F-ADV-P1-007 |
| F-ADV-P2-003 | HIGH | HIGH | Test/Privacy | `src/kani_proofs.rs:255-377` | Composed Kani proof rewrite still misses non-vacuous case (partial F-ADV-P1-005 fix) |
| F-ADV-P2-004 | HIGH | HIGH | Security/Correctness | `src/error.rs:21,44` | `OtError::Parse` overloaded for leak/parse/CLI — exit code 70 can't distinguish |
| F-ADV-P2-005 | HIGH | HIGH | Test/POL-11 | `fuzz/fuzz_targets/scrub_text.rs:73` | scrub_text fuzz has no oracle on output (partial F-ADV-P1-004 fix) |
| F-ADV-P2-006 | HIGH | HIGH | Policy-11 | `.github/workflows/fuzz.yml:33` | Fuzz CI no positive-coverage assertion (dup F-ADV-P1-011) |
| F-ADV-P2-007 | HIGH | HIGH | Privacy | `src/ai/leak_detector.rs:74,96` | Leak-detector error messages echo the leaked value to stderr |
| F-ADV-P2-008 | HIGH | MEDIUM | Privacy | `src/capture_source.rs`, `src/scrub.rs:257` | Capture-source MAC can be unscrubbed when dominant MAC isn't in host list |
| F-ADV-P2-009 | HIGH | HIGH | Privacy/Security | `src/cli.rs:554`, `src/report_md.rs:33` | PCAP path fed unscrubbed to AI markdown header |
| F-ADV-P2-010 | MEDIUM | MEDIUM | Correctness/Privacy | `src/parse/dhcp.rs:69` | DHCP non-ASCII filter creates scrub-map vs report-string mismatch |
| F-ADV-P2-011 | MEDIUM | HIGH | Robustness/Security | `src/scrub.rs:200-216` | merge_map panic reachable from malicious baseline map (dup F-ADV-P1-017) |
| F-ADV-P2-012 | MEDIUM | HIGH | Privacy | `src/ai/leak_detector.rs:127` | ipv6_regex blind to `::1`, `fe80::1`, `2001:db8::`, IPv4-mapped, zoned |
| F-ADV-P2-013 | MEDIUM | MEDIUM | Privacy/Diagnostics | `src/ai/leak_detector.rs:96` | ensure_no_map_values blocks on first hit only |
| **F-ADV-P2-014** | HIGH | HIGH | Infrastructure | `.github/workflows/perf.yml:59` | perf.yml uses `actions/upload-artifact@v7` (doesn't exist) — **active CI breakage** |
| F-ADV-P2-015 | HIGH | HIGH | Test/POL-11 | `tests/cli_smoke.rs:294-336` | Test fixture-skip silently no-ops in CI — coverage illusion |
| F-ADV-P2-016 | LOW | MEDIUM | Robustness | `src/scrub.rs:354,345` | unscrub_text suffix unbounded; O(n²) unmapped Vec |
| F-ADV-P2-017 | LOW | MEDIUM | Policy-11/Supply-chain | `.github/workflows/ci.yml:119` | cargo-deny no positive-coverage assertion |
| F-ADV-P2-018 | LOW | LOW | Privacy | `src/cli.rs:512-533` | --review-scrub prints full scrubbed payload to stderr |
| F-ADV-P2-019 | LOW | HIGH | Correctness | `src/ai/claude_cli.rs:248-258` | which_claude skips Windows .exe/.cmd/.bat |
| F-ADV-P2-020 | LOW | MEDIUM | Correctness (FP) | `src/parse/enip.rs:53-72` | ENIP engineering heuristic can flag benign descriptors |
| F-ADV-P2-021 | LOW | HIGH | Naming | `src/error.rs:21` | Display says "pcap parse error:" for non-parse errors (subsumed by F-ADV-P2-004) |

## Summary

- **Total findings:** 21
- **By severity:** CRITICAL=2, HIGH=11, MEDIUM=4, LOW=4
- **HIGH-confidence:** 13 / 21
- **Trajectory:** 18 → 21 — regression flag investigated:
  - 13 NEW (perimeter expansion — expected for fresh-context)
  - 2 severity-escalations of P1 findings (P1 underrated)
  - 2 partial-fix observations (F-ADV-P1-004 and F-ADV-P1-005 fixes incomplete)
  - 4 duplicates of still-OPEN P1 findings
  - **Root cause: NOT a fix-burst defect.** Mostly perimeter expansion + 2 underclassified P1 severities.
- **Policy compliance:** POL-11 still failing (F-ADV-P2-006, F-ADV-P2-017)
- **Novelty:** FIRST-PASS-DOMINANT (~62% genuinely new findings)
- **Recommendation:** FIX-AND-RERUN on the 2 CRITICAL + the 11 HIGH

## See also

- Full findings document: [pass-2.md](pass-2.md)
- ADV-P1 index: [ADV-P1-INDEX.md](ADV-P1-INDEX.md)
- Tech-debt register: `.factory/tech-debt-register.md`
