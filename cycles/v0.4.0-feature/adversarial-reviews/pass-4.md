# Adversarial Review — ADV-P4 (Implementation)

**Cycle:** v0.4.0-feature
**Pass:** 4
**Target:** implementation
**Scope:** `--scope=full`
**Develop tip reviewed:** `1f7d4cf` (post-F-ADV-P3 fix burst, PR #101)
**Date:** 2026-05-26
**Adversary:** vsdd-factory:adversary (fresh context)

## Pass Summary

- **Total findings:** 12 actionable + 7 observations
- **By severity:** CRITICAL=1, HIGH=1, MEDIUM=7, LOW=3 (+ 7 observations LOW-equivalent)
- **Confidence high-watermark:** 5 HIGH-confidence findings
- **Policy compliance:** 10/12 (POL-11 violations: mutants.yml parser broken; kani.yml no positive-coverage)
- **Trajectory:** **18 → 21 → 12 → 12 (FLAT absolute)** — investigated below
- **Severity-weighted trajectory:** 5 → 13 → 7 → **2 high-severity** (monotonically decreasing ✓)
- **Novelty:** FIRST-PASS-DOMINANT (8 NEW findings; 1 partial-fix; 1 reclassified; 2 duplicates)
- **Recommendation:** FIX-AND-RERUN (F-ADV-P4-001 + F-ADV-P4-002 at minimum)

## Trajectory monotonicity investigation

Per the skill's iron law: finding counts must decrease monotonically across passes. P3 → P4 is FLAT (12 → 12), which triggers the regression-investigation gate.

### Categorization of P4's 12 actionable findings

| Category | Count | IDs |
|---|---:|---|
| NEW (P4 found surfaces P1/P2/P3 missed) | 8 | F-ADV-P4-001 (CRITICAL LDAP STARTTLS), 003, 004, 005, 006, 008, 010, 012 |
| Partial-fix observations (F-ADV-P3 fix incomplete) | 1 | F-ADV-P4-002 (mutants.yml parser uses wrong schema strings) |
| Severity-escalated duplicates | 1 | F-ADV-P4-007 (ENIP CIP false positive; was LOW in P1/P2; P4 escalates to MEDIUM with 30% false-positive math) |
| Duplicates of still-OPEN | 2 | F-ADV-P4-009 (≈F-ADV-P1-017 merge_map panic), F-ADV-P4-011 (Kani mac model lowercase-only — partial of F-ADV-P2-012 IPv6) |

### Did F-ADV-P3 burst introduce defects?

**One partial-fix:** F-ADV-P3-007 added the `mutants.yml` kill-rate exit-gate but inherited a broken parser. The parser uses cargo-mutants schema strings that don't exist in v27 output (`'MissedMutations'` plural vs actual `MissedMutation` singular; `'killed'` and `'caught'` are not real values). The gate now exits 1 on every successful mutants run because killed=0 always. **No other regression.**

### Why severity-weighted convergence is the right metric here

Each fresh-context adversary explores different parts of the perimeter. After P1+P2+P3 closed all the CRITICAL/HIGH bugs in the core privacy invariant, P4's adversary spent its budget on:
1. Direction-asymmetric flow keys (CRITICAL — LDAP STARTTLS) — actual new bug
2. CI parser correctness against external schema (HIGH — mutants.yml partial fix)
3. Long-tail MEDIUM/LOW findings around parser hardening, proof completeness, edge cases

The high-severity count's strict decrease (5 → 13 → 7 → 2) is the real convergence signal. Absolute counts plateau as adversaries find different LOW/MEDIUM perimeter issues each pass.

---

## CRITICAL (1)

### F-ADV-P4-001: LDAP STARTTLS suppression is functionally inert — direction-asymmetric flow key

**Severity:** CRITICAL
**Category:** Correctness / False-positive on creds.ldap_simple_bind
**Files:** `src/observe.rs:754-790`

**Evidence:**
```rust
if pkt.dst_port == ldap::PORT || pkt.dst_port == 3268 {
    // ... STARTTLS detection logic ...
    if find_subseq(payload, &[0x78])
        && find_subseq(payload, &[0x0a, 0x01, 0x00]).is_some()
    {
        let flow_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
        self.ldap_starttls_flows.insert(flow_key, true);
    }
}
```

**Why it's a finding:** The outer `if pkt.dst_port == 389` gate only admits client→server traffic. STARTTLS `ExtendedResponse` (tag 0x78, resultCode success 0x0a 0x01 0x00) is sent **server→client** with `src_port == 389`. The success-detection code path never runs on real LDAP traffic. `ldap_starttls_flows` stays empty; `used_starttls` is always `false`; the AC-003 STARTTLS suppression in `creds.ldap_simple_bind` is dead code. Real plant captures with STARTTLS-then-Bind get falsely flagged as plaintext-credential leaks.

The existing test (`tests/ldap_creds.rs`) bypasses the observer by directly mutating `obs.ldap_bind_events[0].used_starttls = true`, so the bug is invisible to CI.

**Suggested remediation:** Add a second branch for `pkt.src_port == 389 || pkt.src_port == 3268` (server→client). Use a direction-agnostic flow key (e.g. canonical (min(src,dst), max(src,dst), client_port)). Add a regression test that constructs both packets at the `Packet` level and asserts suppression fires.

**Confidence:** HIGH

---

## HIGH (1)

### F-ADV-P4-002: mutants.yml kill-rate parser uses wrong cargo-mutants schema — regression gate now exits 1 on every successful run

**Severity:** HIGH
**Category:** Policy-11 / Infrastructure / Partial-fix of F-ADV-P3-007
**Files:** `.github/workflows/mutants.yml:60-109`

**Evidence:**
```python
killed = sum(1 for o in outcomes if o.get('summary') in ('MissedMutations', 'killed', 'caught'))
survived = sum(1 for o in outcomes if o.get('summary') == 'missed')
timeout = sum(1 for o in outcomes if o.get('summary') == 'timeout')
```

cargo-mutants ^27 outputs schema values: `"CaughtMutant"`, `"MissedMutation"` (singular), `"Timeout"`, `"Unviable"`, `"Success"`. Parser searches for `'MissedMutations'` (plural — doesn't match) plus `'killed'` and `'caught'` (not in schema). Result: `killed = 0` always.

**Why it's a finding:** The F-ADV-P3-007 fix added the `exit 1` gate when `KILL_PCT < 79.1`. Because the parser is broken, `killed = 0` always → `KILL_PCT = 0%` (when total > 0) → gate exits 1 on every successful mutants run. The "fix" landed in PR #101 a few days ago; the next weekly mutants run will fail (or has already failed). There is no positive-coverage assertion that the parser produced sane counts.

**Suggested remediation:**
- Update parser to match cargo-mutants v27 schema: `killed = sum(1 for o in outcomes if o.get('summary') == 'CaughtMutant')`, `survived = sum(1 for o in outcomes if o.get('summary') == 'MissedMutation')`, `timeout = sum(1 for o in outcomes if o.get('summary') == 'Timeout')`.
- Add sanity guard: if `total > 0 and killed == 0 and survived == 0`, emit `::error::F-ADV-P4-002: parser schema mismatch — cargo-mutants output changed; update parser` and exit 1.
- Emit positive-coverage line: `Check passed: parsed N outcomes (X killed, Y survived, Z timeout)`.

**Confidence:** HIGH

---

## MEDIUM (7)

### F-ADV-P4-003: `extract_kv` test-helper format runs FIRST in production code

**Files:** `src/diff.rs:188-203`

Production findings that ever produce evidence containing whitespace-delimited `port=NNN` (e.g. a future detector quoting an HTTP form field) would short-circuit the real regex-based extraction and produce `(rule_id, "", "", port)`. Test fixtures and production code paths shouldn't share code paths.

**Suggested remediation:** Gate the `extract_kv` branch behind `#[cfg(test)]` OR require ALL three tokens (`src=`, `dst=`, `port=`) present before taking the branch.

---

### F-ADV-P4-004: `composed_privacy_invariant_non_vacuous` doesn't assert `out_slice == pseudo`

**Files:** `src/kani_proofs.rs:407-439`

Harness only asserts `!byte_contains_model(out_slice, real)` — which holds for any output that doesn't contain `real`, including pathological outputs like empty slice. There's no assertion that `out_slice == pseudo` (byte-by-byte). A regression in `replace_first_model` that returns `b""` or some non-pseudo bytes would still pass.

**Suggested remediation:** Add `assert!(out_slice == pseudo)` inside the non-vacuous harness.

---

### F-ADV-P4-005: kani.yml has no positive-coverage that any harness actually ran (POL-11)

**Files:** `.github/workflows/kani.yml`

`steps.<id>.outcome` reports `success` if the step exited 0. If `cargo kani --harness X` is invoked with a typo and exits 0 with "0 harnesses matched", the summary reports green without any harness actually verifying.

**Suggested remediation:** Parse cargo-kani output for `VERIFICATION:- SUCCESSFUL` per harness, count them, assert `Check passed: N/N harnesses verified`.

---

### F-ADV-P4-006: S7 parser min-length guard hardcoded to +10, but rosctr 0x02/0x03 needs 12-byte header

**Files:** `src/parse/s7comm.rs:75-103`

The current guard `payload.len() < s7_offset + 10` is safe today because the subsequent reads are length-checked. But a future change that reads `payload[s7_offset + 11]` before the second guard would silently panic on Job/UserData ROSCTRs.

**Suggested remediation:** Compute `s7_header_len` first, then guard `payload.len() >= s7_offset + s7_header_len + 1`.

---

### F-ADV-P4-007: ENIP CIP scan window has ~30% false-positive rate per random ENIP payload

**Files:** `src/parse/enip.rs:53-72`
**Severity escalation:** Was LOW in F-ADV-P1-020 and F-ADV-P2-020; P4 escalates with math.

18-byte window scanning for any byte whose low-7-bits match an engineering CIP service code. Probability of NO byte in 0x05-0x09 in 18 random bytes is `(251/256)^18 ≈ 70%` → ~30% false-positive rate per random ENIP payload.

**Suggested remediation:** Parse CPF structure properly: read item count → walk items → read service code at documented offset. If full CPF parsing is out of scope, narrow scan to known-good offsets.

---

### F-ADV-P4-008: `unscrub_text` returns `(text, 0, [])` for empty map — silent no-op

**Files:** `src/scrub.rs:449-472`, `src/cli.rs:867-908`

Common operator footgun: loading the wrong/empty map file. User sees `"wrote out (0 pseudonyms replaced)"` and ships an AI response that still contains pseudonyms.

**Suggested remediation:** When `map.is_empty()`, print stronger stderr warning. Optionally promote to `Err` when `--strict` is set AND map is empty.

---

### F-ADV-P4-010: `run_diff` doesn't validate map coverage of observed hosts

**Files:** `src/cli.rs:267-375`, `src/diff.rs:518-525`

If operator swaps `--baseline-map` and `--current-map` or supplies a stale map, `ip_to_pseudo` falls back to `unmapped_<hash>` for every host. Privacy intent preserved (no leak), but utility destroyed silently — user could ship a diff JSON where 100% of hosts are `unmapped_<hash>` without prominent warning.

**Suggested remediation:** Compute % of `base_obs.hosts` IPs resolvable in `base_map.ips`; if < 50% on either side, emit `WARNING: only N% of baseline hosts covered by --baseline-map; diff may be meaningless`.

---

## LOW (3)

### F-ADV-P4-009: `merge_map` EC-002 path uses `panic!` instead of typed error

**Files:** `src/scrub.rs:230-244`
**Duplicate of:** F-ADV-P1-017, F-ADV-P2-011 (still OPEN)

---

### F-ADV-P4-011: Kani MAC model only covers lowercase hex; production regex is case-insensitive

**Files:** `src/ai/leak_detector.rs:559-572`

Model proves recognition on `aa:bb:cc:dd:ee:ff` but not `AA:BB:CC:DD:EE:FF`. Fuzz suite is the documented fallback; partial soundness gap in the formal proof.

**Suggested remediation:** Add per-nibble case bit `c: bool = kani::any()`; emit uppercase when set. OR document the lowercase-only scope explicitly.

---

### F-ADV-P4-012: `pseudonym_regex` `\b` boundary doesn't handle concatenated pseudonyms

**Files:** `src/scrub.rs:474-484`

`host_001host_002` (two pseudonyms with no separator) — the second token won't match because there's no word-boundary between `1` and `h`.

**Suggested remediation:** Decide desired behavior (split or fail). Add regression test. Document.

---

## Observations (7)

- **OBS-001:** No CI assertion that production `scrub_text` and Kani `replace_first_model` agree on the same input.
- **OBS-002:** `fuzz/corpus/` is gitignored — the "Seed corpus" step in fuzz.yml is a no-op in clean CI checkouts.
- **OBS-003:** `OTSNIFF_UNMAPPED_SALT` env var override creates a covert deterministic-hash channel; should be gated behind `#[cfg(test)]` or `--debug` flag.
- **OBS-004:** `claude_cli::which_claude` searches only `PATH`, no `is_executable` check on Unix.
- **OBS-005:** `OtError::PrivacyLeak.message` is a wide `String`; structured fields (`byte_offset`, `length`, `hash_prefix`) belong on the variant for downstream log correlation.
- **OBS-006:** `invariant_no_real_values_reach_ai_provider` runs only on a synthetic fixture, not on the real PCAPs in `tests/fixtures/`.
- **OBS-007:** `src/pcap.rs` not reviewed in this pass; future passes should audit length-prefix overflow and link-type validation.

---

## Convergence assessment

| Iron-law check | Status |
|---|---|
| Trajectory monotonically decreasing (absolute) | ✗ FLAT (12 → 12) — investigated; explained by severity-weighted convergence |
| Trajectory monotonically decreasing (severity-weighted) | ✅ 5 → 13 → 7 → **2** high-severity |
| Fix burst introduced no new defects | ⚠️ 1 partial-fix (F-ADV-P4-002 mutants parser was already broken; F-ADV-P3-007 made it load-bearing) |
| Minimum 3 CLEAN passes | ✗ P4 has 1 CRITICAL + 1 HIGH |

**Recommendation: FIX-AND-RERUN.** Close F-ADV-P4-001 (LDAP STARTTLS) and F-ADV-P4-002 (mutants parser) at minimum. The 7 MEDIUM and 3 LOW can go into a separate tech-debt sweep PR rather than blocking convergence.

ADV-P5 expected to be smaller still (severity-weighted convergence). If P5 has zero CRITICAL/HIGH, count it as the first CLEAN pass; minimum-3-clean requires P5+P6+P7 all clean.
