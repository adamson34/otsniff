---
crate: otsniff
generated: 2026-05-26
generator: cargo-mutants 27.0.0
wave: wave-2
cycle: v0.4.0-feature
scope: src/diff.rs (S-6.02 — new wave-2 product module)
status: PASSED-WITH-DISPOSITIONS
---

# Wave-2 Mutation Report — `otsniff` crate

## Scope rationale

The wave-2 mutation gate is the compensating control for facade-mode stories
(BC-6.21.001/002). Wave-2's three facade stories added **verification
infrastructure**, not mutable product logic in the configured examine scope:

- **S-3.03** — `.cargo-mutants.toml` config + triage rules
- **S-3.04** — `fuzz/` harnesses
- **S-4.04** — `kani-proofs/` + `src/kani_proofs.rs` (`#[cfg(kani)]`, not compiled in normal builds)

The repo's `.cargo-mutants.toml` deliberately scopes the *standing* mutation
gate to security-critical modules (`findings/`, `parse/`, `scrub.rs`,
`leak_detector.rs`) — unchanged by wave-2, last validated at 84.1% in wave-1.

The one strict-TDD wave-2 story, **S-6.02**, added `src/diff.rs`. `diff.rs` is
a comparison/rendering module — outside the standing examine scope (same
category as the excluded `report*.rs`). It was nonetheless mutation-tested for
wave-gate diligence, since it is new product code.

## Summary — `src/diff.rs`

| Metric | Run 1 (as-merged) | Run 2 (gate tests) | Run 3 (after ADV-W2 remediation) |
|---|---|---|---|
| Mutants generated | 54 | 54 | 58 |
| Unviable (compile fail) | 2 | 2 | 2 |
| Viable (testable) | 52 | 52 | 56 |
| Caught | 37 | 42 (+5) | **47** (+5) |
| Missed | 15 | 10 | 9 |
| Kill rate (caught / viable) | 71.2% | 80.8% | **83.9%** |
| Effective (caught + dispositioned) | — | 100% | **100%** |

Kill-rate gate (BC-6.21.002), integer arithmetic: `47 * 100 / 56 = 83 >= 80` → **PASS**.
All 9 surviving mutants dispositioned below.

Run 3 reflects the Gate-3 adversarial-review remediation (PR on develop): `resolve_endpoint`
now emits `unmapped_label` on a genuine map-miss (ADV-W2-001) and recognises all pseudonym
prefixes (ADV-W2-004). That refactor removed the one equivalent `||`→`&&` survivor (now
killable `is_pseudonym` mutants, caught) and the `unmapped_label` fallback is killed by the
updated test. `src/diff.rs` was also added to the standing `.cargo-mutants.toml` scope (ADV-W2-002).

## Gate remediation (tests added)

Six correctness-relevant survivors were killed by adding tests:

- `src/diff.rs` inline `#[cfg(test)] mod tests` — `finding_diff_key` all-three-token
  guard (2 `&&` mutants), `resolve_endpoint` whole-body replacement (2 mutants),
  `is_pseudonym` prefix logic + `unmapped_label` map-miss fallback (ADV-W2 remediation).
- `tests/s_6_02_diff_subcommand.rs::test_ac_004_flow_volume_doubled_triggers_shift` —
  added `fs.src`/`fs.dst` pseudonym assertions, killing the `ip_to_pseudo`
  `==`→`!=` lookup mutant (privacy-adjacent: wrong pseudonym on a flow shift).

## Surviving-mutant dispositions (Run 3 — 9 survivors)

| Mutant | File | Line | Mutation | Disposition | Notes |
|--------|------|------|----------|-------------|-------|
| compute_with_multiplier delete `!` | src/diff.rs | 356 | delete `!` (EC-002 guard) | **B** | EC-002 block contains only `eprintln!(...)` — no `return`, no state change. Mutation alters whether a stderr diagnostic prints; the returned `Diff` value is identical. No assertion on `Diff` data can distinguish; stderr-text assertions would be brittle. Output-equivalent. |
| compute_with_multiplier `&&`→`||` | src/diff.rs | 357 | replace `&&` with `\|\|` (EC-002 guard) | **B** | Same EC-002 diagnostic-only block. Output-equivalent. |
| compute_with_multiplier delete `!` | src/diff.rs | 357 | delete `!` (EC-002 guard) | **B** | Same EC-002 diagnostic-only block. Output-equivalent. |
| compute_with_multiplier `&&`→`||` | src/diff.rs | 358 | replace `&&` with `\|\|` (EC-002 guard) | **B** | Same EC-002 diagnostic-only block. Output-equivalent. |
| proto_label → `String::new()` | src/diff.rs | 748 | replace body with `String::new()` | **C** | Cosmetic protocol-label mapping (`6→tcp`, `17→udp`, `1→icmp`, else `ip/{n}`). The repo `.cargo-mutants.toml` excludes rendering/label code as "output format, not security logic." Asserting exact label strings is the brittle, low-value test that policy excludes. |
| proto_label → `"xyzzy".into()` | src/diff.rs | 748 | replace body with `"xyzzy".into()` | **C** | Same — cosmetic label string, out of mutation scope per repo policy. |
| proto_label delete arm `6` | src/diff.rs | 749 | delete match arm (tcp) | **C** | Same — cosmetic label string. |
| proto_label delete arm `17` | src/diff.rs | 750 | delete match arm (udp) | **C** | Same — cosmetic label string. |
| proto_label delete arm `1` | src/diff.rs | 751 | delete match arm (icmp) | **C** | Same — cosmetic label string. |

**Disposition legend:** A = new test (6 mutants killed across Run 2 + Run 3). B = dead-code /
output-equivalent (4 — EC-002 diagnostic-only guard). C = explicit waiver, cosmetic label
strings out of mutation scope per `.cargo-mutants.toml` (5). The previously-equivalent
`resolve_endpoint` `||`→`&&` survivor was eliminated by the ADV-W2-001 refactor.

## Verdict

`src/diff.rs` kill rate **83.9% ≥ 80%** floor (Run 3, post-remediation); all 9
survivors individually dispositioned (4×B, 5×C). `src/diff.rs` is now part of the
standing `.cargo-mutants.toml` scope. Security-critical scope otherwise unchanged
from wave-1. **Gate 2b (mutation testing): PASS-WITH-DISPOSITIONS.**
