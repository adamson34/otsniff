---
artifact_type: mutation-report
wave: wave-1
crate: otsniff
generated: 2026-05-19
generator: cargo-mutants 27.0.0
scope: --in-diff against 89168bd..develop (this session's deliveries)
---

# Wave-1 Mutation Report — `otsniff` crate

## Summary

| Metric | Value |
|---|---|
| Total mutants generated | 178 |
| Caught | 78 |
| Missed | 81 |
| Unviable (compile fail) | 15 |
| Timeouts (>60s) | 4 |
| Wall time | 8 minutes |
| Jobs | 12 (parallel) |
| Timeout per mutant | 60s |
| Scope | session-diff (`cargo mutants --in-diff /tmp/wave-session.diff`) |

## Kill Rates

Per BC-6.21.002, the threshold is `killed * 100 / total >= 80`.

| Computation | Numerator | Denominator | Rate | Pass (≥80%)? |
|---|---|---|---|---|
| Strict (skill formula) | 78 killed | 178 total | **43.8%** | ❌ FAIL |
| Excluding unviable + timeouts | 78 | 159 | 49.1% | ❌ FAIL |
| Excluding `#[cfg(kani)]` artifacts | 78 | 127 (178 − 51 kani) | 61.4% | ❌ FAIL |

**The strict skill formula yields 43.8%. The gate fails.**

## Categorical Breakdown of 81 Missed Mutants

### Category 1: `#[cfg(kani)]` proof harnesses (51 mutants) — Disposition B

Stories S-4.01, S-4.02, S-4.03 added formal proof harnesses inside `#[cfg(kani)]` blocks. These are dead code in normal builds (only compile under `cargo kani`). `cargo-mutants` mutates them but no test exercises them, so 100% are missed. This is a categorical artifact, not a real test gap.

Files affected:
- `src/scrub.rs` — `kani_proofs::scrub_roundtrip_bounded` mutations
- `src/ai/leak_detector.rs` — `kani_proofs::leak_regex_ipv4/ipv6/mac` + `map_value_substring` mutations

**Disposition B (dead-code-equivalent):** these mutants are unreachable in normal cargo builds. Their semantic correctness is verified by the `cargo kani --harness <name>` runs in `.github/workflows/kani.yml`. Future improvement: add a `cargo-mutants` exclude rule for `#[cfg(kani)]` blocks.

### Category 2: Production code missed mutants (30 mutants) — Disposition required

These are real test gaps in wave-1 production code. Each requires individual disposition (A: new test, B: dead-code argument, or C: explicit waiver).

| Mutant | File | Line | Mutation | Disposition | Notes |
|--------|------|------|----------|---------|------|
| 1 | src/ai/claude_cli.rs | 129 | delete `!` in `analyze` | A (needed) | Path: error handling around verbose toggle; existing tests don't assert error message shape |
| 2 | src/ai/claude_cli.rs | 72 | return Ok("") | A | analyze() return value not checked for non-empty in unit tests |
| 3 | src/ai/claude_cli.rs | 72 | return Ok("xyzzy") | A | Same as above — return value content not asserted |
| 4 | src/ai/claude_cli.rs | 87 | replace `\|\|` with `&&` | A | Verbose-flag OR-with-TTY condition; needs test asserting both branches |
| 5-6 | src/findings/modbus_recon.rs | 82 | `>` → `==` or `>=` (threshold) | A | Severity threshold (5 unit IDs); add boundary test at 4/5/6 IDs |
| 7-8 | src/findings/weak_tls_cipher.rs | 71 | cipher_name → "" or "xyzzy" | A | Display strings not asserted; add `assert_eq!(cipher_name(0x0004), "TLS_RSA_WITH_RC4_128_MD5")` test |
| 9-14 | src/findings/weak_tls_cipher.rs | 72-77 | delete match arm 0x0001/2/4/5/9/A | A | Each weak-cipher code needs explicit test that cipher_name returns the right string |
| 15-26 | src/parse/ldap.rs | 47, 58, 64, 73, 82, 126 | various `>` `<` `+` `-` `*` `==` `>=` `\|\|` `&&` mutations | A | Bounds-check and arithmetic mutations in `recognize_bind_request` and `skip_tlv`. Existing parser tests don't exercise boundary conditions. Need length-mismatch + arithmetic-edge tests. |
| 27 | src/parse/rdp.rs | 54 | replace `\|\|` with `&&` | A | TPKT header byte check OR condition |
| 28-29 | src/parse/rdp.rs | 66 | replace `&` with `\|` or `^` | A | Selected-protocol bit check; add test with various protocol values |
| 30 | src/parse/rdp.rs | 72 | replace `!=` with `==` | A | RDP_NEG_RSP type field check |

## Verdict

**GATE STATUS: ❌ FAIL** — kill rate (43.8%) below 80% floor.

### Findings

1. **51 cfg(kani) mutants are categorically Disposition B.** The mutation testing tool doesn't understand `#[cfg(kani)]` semantics. These represent a tooling limitation, not a test gap.

2. **30 production mutants represent real test debt.** Most are concentrated in:
   - LDAP parser (S-2.05) — 12 mutants
   - Weak TLS cipher detector (S-2.07) — 8 mutants
   - RDP parser (S-2.08) — 3 mutants
   - claude_cli AI provider — 4 mutants
   - modbus_recon threshold — 2 mutants
   - others — 1 mutant

3. **Test gaps reveal a pattern.** The facade-mode delivery skipped the strict TDD Red Gate density check. Tests that DO exist cover happy paths but skip:
   - Numeric boundary values (off-by-one tests for thresholds)
   - Display-string content assertions (catalog/metadata round-trips)
   - Error-path coverage in `analyze()`
   - Parser bounds-check edge cases

### Recommended Next Steps

The gate FAILS until production-code missed mutants are addressed. Options:

**Option A (recommended):** Write the ~15 follow-up tests to kill the 30 production mutants. Estimated 2-4 hours of focused test-writing. Re-run mutation testing to confirm ≥80% kill rate.

**Option B:** File 30 individual mutant dispositions (mostly Disposition C waivers). Honest acknowledgment that these test gaps exist; defer to a future tech-debt sweep. **The skill explicitly forbids blanket waivers** — each requires a named entry with rationale.

**Option C:** Accept the gate failure, document the kill rate as the wave-1 baseline, and set a tightening trajectory for future waves. Not skill-compliant but transparent about the state of facade-mode test coverage.

## Reference

- Skill: `vsdd-factory:wave-gate` mutation testing section
- BC anchors: BC-6.21.001 (mutation report committed), BC-6.21.002 (≥80% kill rate)
- Tool: cargo-mutants v27.0.0, installed during wave-1 gate run
- Output directory: `/tmp/mutants/mutants.out/` (transient — not committed)
