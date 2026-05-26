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

| Metric | Run 1 (as-merged) | Run 2 (after gate tests) |
|---|---|---|
| Mutants generated | 54 | 54 |
| Unviable (compile fail) | 2 | 2 |
| Viable (testable) | 52 | 52 |
| Caught | 37 | **42** (+5) |
| Missed | 15 | 10 |
| Kill rate (caught / viable) | 71.2% | **80.8%** |
| Effective (caught + dispositioned) | — | **100%** |

Kill-rate gate (BC-6.21.002), integer arithmetic: `42 * 100 / 52 = 80 >= 80` → **PASS**.
All 10 surviving mutants dispositioned below.

## Gate remediation (Run 1 → Run 2)

Five correctness-relevant survivors were killed by adding tests:

- `src/diff.rs` inline `#[cfg(test)] mod tests` — `finding_diff_key` all-three-token
  guard (2 `&&` mutants), `resolve_endpoint` whole-body replacement (2 mutants).
- `tests/s_6_02_diff_subcommand.rs::test_ac_004_flow_volume_doubled_triggers_shift` —
  added `fs.src`/`fs.dst` pseudonym assertions, killing the `ip_to_pseudo`
  `==`→`!=` lookup mutant (privacy-adjacent: wrong pseudonym on a flow shift).

## Surviving-mutant dispositions

| Mutant | File | Line | Mutation | Disposition | Notes |
|--------|------|------|----------|-------------|-------|
| resolve_endpoint `||`→`&&` | src/diff.rs | 289 | replace `\|\|` with `&&` | **B** | Equivalent. Guard `s.is_empty() \|\| s.starts_with("host_")` short-circuits to `return s`. With `&&` the guard is never true (an empty string never starts with `host_`), so control always falls to `resolve_ip_to_pseudonym(s).unwrap_or(s)`. For both `""` and `host_NNN` that fallthrough returns the input unchanged (a `host_` pseudonym is never a real map *value*; `""` misses the map). Output identical for all inputs. |
| compute_with_multiplier delete `!` | src/diff.rs | 342 | delete `!` (EC-002 guard) | **B** | EC-002 block contains only `eprintln!(...)` — no `return`, no state change. Mutation alters whether a stderr diagnostic prints; the returned `Diff` value is identical. No assertion on `Diff` data can distinguish; stderr-text assertions would be brittle. Output-equivalent. |
| compute_with_multiplier `&&`→`||` | src/diff.rs | 343 | replace `&&` with `\|\|` (EC-002 guard) | **B** | Same EC-002 diagnostic-only block. Output-equivalent. |
| compute_with_multiplier delete `!` | src/diff.rs | 343 | delete `!` (EC-002 guard) | **B** | Same EC-002 diagnostic-only block. Output-equivalent. |
| compute_with_multiplier `&&`→`||` | src/diff.rs | 344 | replace `&&` with `\|\|` (EC-002 guard) | **B** | Same EC-002 diagnostic-only block. Output-equivalent. |
| proto_label → `String::new()` | src/diff.rs | 734 | replace body with `String::new()` | **C** | Cosmetic protocol-label mapping (`6→tcp`, `17→udp`, `1→icmp`, else `ip/{n}`). The repo `.cargo-mutants.toml` excludes rendering/label code as "output format, not security logic." Asserting exact label strings is the brittle, low-value test that policy excludes. |
| proto_label → `"xyzzy".into()` | src/diff.rs | 734 | replace body with `"xyzzy".into()` | **C** | Same — cosmetic label string, out of mutation scope per repo policy. |
| proto_label delete arm `6` | src/diff.rs | 735 | delete match arm (tcp) | **C** | Same — cosmetic label string. |
| proto_label delete arm `17` | src/diff.rs | 736 | delete match arm (udp) | **C** | Same — cosmetic label string. |
| proto_label delete arm `1` | src/diff.rs | 737 | delete match arm (icmp) | **C** | Same — cosmetic label string. |

**Disposition legend:** A = new test (5 mutants, killed in Run 2). B = dead-code /
output-equivalent (5). C = explicit waiver, out of mutation scope per `.cargo-mutants.toml` (5).

## Verdict

`src/diff.rs` kill rate **80.8% ≥ 80%** floor; all 10 survivors individually
dispositioned (5×B, 5×C). Security-critical scope unchanged from wave-1.
**Gate 2b (mutation testing): PASS-WITH-DISPOSITIONS.**
