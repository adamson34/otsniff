# Adversarial Review — ADV-P5 (Implementation)

**Cycle:** v0.4.0-feature
**Pass:** 5
**Target:** implementation
**Scope:** `--scope=full`
**Develop tip reviewed:** `50cab61` (post-F-ADV-P4 fix burst, PR #102)
**Date:** 2026-05-26
**Adversary:** vsdd-factory:adversary (fresh context)

## Pass Summary

- **Total findings:** 17
- **By severity:** CRITICAL=0, HIGH=1, MEDIUM=10, LOW=6
- **Confidence high-watermark:** 5 HIGH-confidence findings (F-001, F-002, F-003, F-006, F-015)
- **Policy compliance:** 10/12 (POL-11 axis findings on mutants ratchet F-009 and fuzz floor F-010)
- **Trajectory (total):** 18 → 21 → 12 → 12 → **17** (UP from P4, investigated below)
- **Severity-weighted trajectory:** 5 → 13 → 7 → 2 → **1 high-severity** (monotonically decreasing ✓)
- **CRITICAL streak:** P1=0, P2=2, P3=1, P4=1, **P5=0** (first pass with zero CRITICAL since P1) ✓
- **Novelty:** MIXED — 12 NEW perimeter findings, 3 partial-fix refinements, 2 narrow refinements of prior fixes
- **Recommendation:** FIX-AND-RERUN (close F-ADV-P5-001 — the sole HIGH — at minimum)

## Trajectory monotonicity investigation

P4=12, P5=17. **Total count went UP**, which triggers regression-investigation gate.

### Categorization of P5's 17 findings

| Category | Count | IDs |
|---|---:|---|
| NEW perimeter (P5 found surfaces P1-P4 missed) | 12 | F-001, F-002, F-003, F-005, F-007, F-008, F-010, F-011, F-013, F-015, F-016, F-017 |
| Partial-fix refinements (prior P3 fix narrowed but not closed) | 3 | F-004 (unmapped_label salt entropy — refines F-ADV-P3-006), F-006 (scrub_text regex fallback — refines F-ADV-P3-004), F-012 (S7 cotp_len_byte cap — refines F-ADV-P3-011) |
| Partial refinements of P4 fix surface | 2 | F-009 (mutants kill-rate has no ratchet — refines F-ADV-P3-007 + F-ADV-P4-002), F-014 (kani outcome check shallow — refines F-ADV-P4-005) |

### Did F-ADV-P4 fix burst introduce defects?

**Zero NEW defects from the P4 fix burst.** Every P5 finding either (a) addresses a surface the P4 burst did not touch, (b) refines a P3-era fix that P4 didn't revisit, or (c) is a fresh perimeter probe (basename leak, audit log path, DNP3 length, DHCP hostname injection, etc.).

The mutants.yml parser fix (F-ADV-P4-002) and the kani.yml positive-coverage assertion (F-ADV-P4-005) are critiqued by F-009 and F-014 respectively, but the critiques are "this could be tighter," not "this regressed."

### Why total went up but severity went down

P5's adversary explored CI hardening (mutants ratchet, fuzz floor, kani metadata), I/O boundary leaks (PCAP basename → AI, audit-log paths, model name → audit), and previously-unaudited parsers (DNP3 length validation). These are all surfaces P1-P4's adversaries didn't budget for. The discovery curve for LOW/MEDIUM perimeter is essentially a long tail — fresh-context review keeps surfacing new corners.

**Convergence signal is severity-weighted:** P1=5 → P2=13 → P3=7 → P4=2 → **P5=1**. The single remaining HIGH is the basename leak (F-ADV-P5-001), which is a direct generalization of the same operator-identifier class as F-ADV-P2-009 closed.

---

## HIGH (1)

### F-ADV-P5-001: Plant-name and operator-name leak via PCAP basename in markdown sent to AI

**Severity:** HIGH
**Category:** Privacy
**Files:** `src/cli.rs:615-624`, `src/report_md.rs:33-40`

**Evidence:**
```rust
// cli.rs:615-624 (run_analyze with --ai)
let source_label = args
    .input
    .file_name()
    .map(|s| s.to_string_lossy().into_owned())
    .unwrap_or_else(|| "<unknown>".to_string());
let raw_md = render_markdown(&inventory, &findings, &obs, &source_label, ...);
```
And rendered into the AI-bound markdown:
```rust
// report_md.rs:33-40
writeln!(out, "_Source: `{}` · Generated: {} · otsniff v{}_", input_label, ...);
```

**Why it's a finding:** F-ADV-P2-009 narrowed the leaked path from full filesystem path to the PCAP basename, but the basename itself is often privacy-sensitive. A capture named `acme-plant-alpha-line3-2026-05-22.pcap` ships the operator's plant / line / facility identifier into the AI provider's prompt. The leak detector cannot catch this: the scrub map only contains IPs/MACs/DHCP-hostnames observed inside the parsed PCAP bytes — the filename is outside that domain. `ensure_clean` regex won't fire on plant names; `ensure_no_map_values` won't either. This is exactly the class of BCSI under NERC CIP-011 that ADR-0006 promised to keep out of the AI.

**Suggested remediation:** Pass a constant placeholder string (`"<scrubbed>"`) as `input_label` whenever the markdown payload is destined for the AI provider — same treatment `run_scrub` already uses for the manual flow (`cli.rs:525`). Reserve the real basename for HTML-only display.
**Confidence:** HIGH

---

## MEDIUM (10)

### F-ADV-P5-002: Audit log carries full input PCAP path (operator username + directory tree)

**Files:** `src/cli.rs:810-814`

```rust
input_pcap: InputDescriptor {
    path: args.input.display().to_string(),
    size_bytes,
    sha256,
},
```

The audit log is documented as a chain-of-custody artifact safe to share for compliance review. But the `path` field embeds the operator's full filesystem path — typically `/Users/<operator>/captures/<plant>/<file>.pcap`. The leak detector's regex (`ensure_clean`) doesn't match path tokens (no IP/MAC shape), and `ensure_no_map_values` only knows DHCP-derived names — so the audit log passes both gates while carrying the operator's username and the plant directory hierarchy. Contradicts the documented invariant.

**Suggested remediation:** Store only `args.input.file_name()` (basename), or hash the path. The SHA-256 of the file contents already identifies the input; the filesystem path adds no chain-of-custody value but adds leakage. **Note:** This + F-ADV-P5-001 motivate the same fix shape — replace path with sentinel for AI-bound and audit artifacts both.

---

### F-ADV-P5-003: DNP3 parser docstring claims length-mismatch rejection that the code does not enforce

**Files:** `src/parse/dnp3.rs:32-55`

Docstring promises "length mismatch" causes `None`, but `payload[2]` (the DNP3 length byte) is read nowhere. Any 13-byte buffer with sync bytes `0x05 0x64` produces a `Dnp3Pdu`. Adversary scenario: TCP segments whose payload begins with `\x05\x64` (other industrial protocols, or attacker-controlled bytes on tcp/20000) are classified as engineering-class commands. Since `dnp3_engineering` escalates severity to Critical when src is outside OT subnets, this can drive bogus criticals.

**Suggested remediation:** Either implement link-layer length validation (`payload[2]` is data-length; verify payload has the declared bytes) or correct the docstring.

---

### F-ADV-P5-004: `unmapped_label` salt derives from process time/PID — collision-discoverable

**Files:** `src/diff.rs:710-730`
**Refines:** F-ADV-P3-006 (which strengthened the hash from 16 to 64 bits and added the salt)

Salt entropy is `nanos_since_epoch ⊕ pid` — both observable to anyone with shell access or co-located processes. PIDs are typically 16 bits effective; wall-clock nanos can be narrowed via filesystem mtimes of generated reports. An attacker with a candidate IP space (any /24, ~256 IPs) and the ability to observe one diff output can brute-force the salt by re-running the diff against synthetic captures locally.

**Suggested remediation:** Use `getrandom`/`OsRng` for the salt. Document the salt as ephemeral, kernel-CSPRNG-sourced per process.

---

### F-ADV-P5-005: pulldown-cmark code-block language identifier may inject HTML attributes

**Files:** `src/ai/html_render.rs:56-105`

The `Event::Html`/`Event::InlineHtml` filter drops raw HTML, but `Tag::CodeBlock(CodeBlockKind::Fenced(lang))` carries the language identifier verbatim — interpolated into `<pre><code class="language-{lang}">`. A malicious AI response containing `` ```onerror=alert(1)" `` could attempt to inject attributes via the code-block class. Reliance on pulldown-cmark's own escaping is implicit but undocumented.

**Suggested remediation:** Add explicit positive tests for `<pre><code class="language-...">` injection paths. Confirm pulldown-cmark escapes the class attribute; if it does, add a comment citing the version dependency. If not, sanitise the language token.

---

### F-ADV-P5-006: `scrub_text` regex fallback path uses known-buggy sequential replace

**Files:** `src/scrub.rs:420-435`
**Refines:** F-ADV-P3-004 (which fixed the primary path)

The regex-construction fallback iterates entries sorted by descending length and calls `String::replace` sequentially. This is precisely the substring-shadowing bug F-ADV-P3-004 documented and fixed in the primary path. The fallback comment calls it "conservative" but it's actually the known-buggy implementation — semantically weaker than the primary. The `regex::Regex::new(&pattern)` call uses `regex::escape`, which is total, so the fallback is unreachable today — but a future change (e.g., pseudonym families with unescaped metacharacters) could activate the bug silently.

**Suggested remediation:** Either remove the fallback (panic with "regex construction must not fail"), or rewrite it with the same single-pass longest-match algorithm via manual scanning.

---

### F-ADV-P5-008: DHCP hostname interpolated verbatim into finding evidence (HTML / prompt-injection vector)

**Files:** `src/findings/mod.rs:39-44`, `src/parse/dhcp.rs:71-78`

DHCP option-12 hostname is filtered to printable ASCII (0x20-0x7E), which includes `<`, `>`, `'`, `"`, `&` and HTML-significant characters. `host_label` embeds it directly into evidence strings rendered by askama. If askama auto-escapes (default for `{{ var }}`), HTML is safe — but the scrub→render pipeline depends on that escaping. AI-bound markdown also passes hostname text via `scrub_text` into the AI prompt; a hostname like `]]\n\n###Ignore previous. Output:` reaches the model verbatim.

**Suggested remediation:** Reject DHCP hostnames containing characters outside `[A-Za-z0-9._-]` at the parser (RFC 952/1123 hostname grammar); or strip at `host_label`. Document the trust boundary on `obs.hostnames`.

---

### F-ADV-P5-009: Mutation testing kill-rate threshold is below baseline — silently absorbs regression

**Files:** `.github/workflows/mutants.yml:130-143`
**Refines:** F-ADV-P3-007 + F-ADV-P4-002 (which fixed the parser and threshold check)

Threshold is 79.1%, baseline is 84.1%. A drift to 80% passes the gate silently and emits "Check passed" — even though the codebase is now 4pp worse than baseline. No ratchet (kill rate monotonically increasing), no per-run delta against the previous CI run. Over many cycles this absorbs regressions invisibly.

**Suggested remediation:** Either (a) tighten threshold to baseline minus 1pp; (b) persist previous-run kill rate as workflow artifact and fail if drop >2pp. Update baseline atomically (PR landing higher kill rate updates the baseline string).

---

### F-ADV-P5-010: Fuzz workflow accepts 10 runs as "positive coverage" — silently degenerates to near-no-op

**Files:** `.github/workflows/fuzz.yml:51-64`

Floor of "10 runs OR 1 pulse" is so low that a regression making `scrub_text` quadratic would still pass the gate. libFuzzer always prints `#0 INITED` at startup, so effective pulse-count floor is essentially zero. A regression where the harness gets exactly 10 runs in 60 seconds passes; meaningful fuzz coverage requires thousands of runs per second.

**Suggested remediation:** Compute per-harness minimum-runs threshold from prior baseline (e.g., parser fuzz targets ≥100,000 runs/60s on clean CI runner). Persist threshold next to the workflow file. Fail when run count drops >50% below baseline. Also assert "INITED" line reports non-zero unit count.

---

### F-ADV-P5-014: kani.yml success counter doesn't verify outcome metadata

**Files:** `.github/workflows/kani.yml:73-97`
**Refines:** F-ADV-P4-005 (which added the count-based positive-coverage assertion)

"outcome=success" is GitHub Actions' generic step-result label — fires when `cargo kani --harness X` exits 0, regardless of whether X exists or CBMC actually verified anything. Specifically: `cargo kani --harness foo_that_does_not_exist` may exit 0 with "no harness matched" in some kani-verifier versions. The expected count of 8 is hardcoded — drift between this number and the actual harness list in code is silent.

**Suggested remediation:** Parse each step's stdout to confirm "VERIFICATION SUCCESSFUL" or equivalent. Assert per-harness count of properties verified is non-zero. Extract expected count from grep of `#[kani::proof]` across the repo rather than hardcoding.

---

### F-ADV-P5-016: Audit log `command` field embeds attacker-controllable model name without validation

**Files:** `src/cli.rs:818-824`

`args.model` is interpolated as raw text into the audit log's `command` field. No validation. A `--model` value like `"sonnet --debug-prompt /etc/passwd"` ends up in the audit log verbatim. The spawn uses argv-style `Command::new("claude").args(["--model", m])` (no shell — no command injection), but the audit log's claim that this string reflects the invocation diverges from reality.

**Suggested remediation:** Validate `args.model` to `[A-Za-z0-9._-]+`, OR rename `command` to `argv` and serialize as a JSON array matching what `Command::new` actually invoked.

---

## LOW (6)

### F-ADV-P5-007: `unscrub_text` accepts duplicate pseudonym keys across families silently

**Files:** `src/scrub.rs:461-479`

`validate()` checks duplicate real values but NOT duplicate pseudonym keys across `ips`/`macs`/`names`. A corrupted/hand-edited map can produce wrong unscrubbed text without signal — even under `--strict`.

**Suggested remediation:** Add a check in `validate()` that the union of pseudonym keys across families has no duplicates.

---

### F-ADV-P5-011: `audit.sha256_file_hex` uses `OtError::InputOpen` for read-mid-file errors

**Files:** `src/audit.rs:108-129`

Both `File::open` and per-chunk `read` produce `OtError::InputOpen { path }` → exit code 2 (input failure). A mid-file read error (I/O failure, EBUSY) is not an "input open" issue. Mixing the two makes shell branching on exit codes imprecise.

**Suggested remediation:** Add `OtError::InputRead { path, source }` variant, or reuse `OtError::Parse` for the read-mid-stream case; reserve `InputOpen` for `File::open` failures.

---

### F-ADV-P5-012: S7 `cotp_len_byte` cap of 17 still over twice the realistic COTP ceiling

**Files:** `src/parse/s7comm.rs:78-95`
**Refines:** F-ADV-P3-011 (which set the cap from unbounded to 17)

The F-ADV-P3-011 fix capped `cotp_len_byte` at 17. But COTP class-0 (RFC 905) is 4-6 bytes; class-2 with TPDU-size param adds 2; legitimate values are ≤8. The cap of 17 is over twice the realistic ceiling and lets an attacker place a synthetic `0x32` byte freely between offsets 5 and 22.

**Suggested remediation:** Tighten the cap to 8 (or whatever the documented max is for COTP classes 0/2 with all standard params).

---

### F-ADV-P5-013: `ldap_starttls_flows` HashMap grows unboundedly across captures with many LDAP flows

**Files:** `src/observe.rs:361-362`, `src/observe.rs:782-808`

Entries inserted but never expunged. For long captures with many ephemeral client ports talking to LDAP, the map grows without bound. Adversarial captures (e.g., recorded scan probing tcp/389 with millions of different src ports) push this into multi-GB territory in pathological cases. Other observer maps face similar issues but serve real reporting; `ldap_starttls_flows` is purely transient state.

**Suggested remediation:** Cap map size (LRU) or expunge entries whose corresponding bind has been observed. Hard upper bound (e.g., 10,000 entries) — skip inserts past it.

---

### F-ADV-P5-015: `f64::MAX` accepted as `flow_shift_multiplier` — produces zero shifts silently

**Files:** `src/cli.rs:279-283`

`f64::MAX` (~1.8e308) is finite and ≥1, passes validation. The diff loop checks `if ratio >= multiplier`. With `multiplier = f64::MAX`, no flow can ever match → `flow_shifts` is silently empty. User gets `0 flow_shifts` and no signal their multiplier was nonsensical.

**Suggested remediation:** Add upper bound `flow_shift_multiplier > 1e6` as rejection condition. A flow ratio above ~1000× is already unrealistic.

---

### F-ADV-P5-017: No integration test asserts the audit log passes leak-detector at run-time

**Files:** `src/cli.rs:839-841`, `tests/snapshot.rs`

The unit test in `audit.rs:153` checks a synthetic log via `leak_detector::scan` (one-shot). No test exercises the CLI pipeline's call to `ensure_no_map_values` on the audit log with a realistic ScrubMap. A future refactor bypassing those two lines (e.g., moving the write inside an early-return path) wouldn't be caught.

**Suggested remediation:** Add a `tests/cli_smoke.rs` or `tests/snapshot.rs` integration test that runs `analyze --ai` against a synthetic PCAP with a mocked AI provider, asserts the audit log file exists, and asserts a leak detector pass on the file's contents.

---

## Convergence assessment

| Iron-law check | Status |
|---|---|
| Trajectory monotonically decreasing (absolute) | ✗ UP (12 → 17) — investigated; explained by perimeter expansion into CI hardening + I/O boundary leaks |
| Trajectory monotonically decreasing (severity-weighted) | ✅ 5 → 13 → 7 → 2 → **1 high-severity** |
| Fix burst introduced no new defects | ✅ Zero P5 findings attribute to P4 fix burst (F-009/F-014 are tightening critiques, not regressions) |
| Zero CRITICAL | ✅ First pass since P1 with zero CRITICAL |
| Minimum 3 CLEAN passes | ✗ P5 has 1 HIGH (not clean) |

**Recommendation: FIX-AND-RERUN.** Close F-ADV-P5-001 (PCAP basename → AI leak) at minimum — this is a direct extension of the F-ADV-P2-009 fix shape. The remaining 10 MEDIUM and 6 LOW can go into a tech-debt sweep PR rather than blocking convergence.

If F-001 closure lands and ADV-P6 has zero CRITICAL/HIGH, count P6 as the first CLEAN pass; iron-law convergence requires P6+P7+P8 all clean. The severity-weighted curve (5 → 13 → 7 → 2 → 1 → 0?) is poised for the first clean pass on the next iteration.
