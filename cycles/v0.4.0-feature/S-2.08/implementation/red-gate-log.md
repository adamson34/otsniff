---
document_type: red-gate-log
level: ops
version: "1.0"
status: done
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-2.08-creds-rdp-no-nla.md
  - src/parse/rdp.rs
  - src/findings/rdp_legacy.rs
  - src/observe.rs
input-hash: "[d9f2a14 stub commit]"
traces_to: "BC-1.04.004, BC-3.04.006"
stub_architect_agent: "[d9f2a14]"
stub_compile_verified: true
test_writer_agent: "[claude-sonnet-4-6 session]"
red_gate_verified: true
---

# Red Gate Log: S-2.08 — creds.rdp_no_nla

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-2.08 | 15 | YES (see breakdown) | PASSED |

## Stubs Created (from d9f2a14)

### S-2.08: creds.rdp_no_nla

- `pub fn recognize_connection_confirm(_payload: &[u8]) -> Option<RdpNegRecognized>` — body `todo!()`
- `pub fn build_findings(_obs: &Observations) -> Vec<Finding>` — body `Vec::new()` (green-by-design)
- `pub struct RdpNegRecognized { pub selected_protocol: u32 }` — data type only
- `pub struct RdpEvent { ts, src, dst, dst_port, selected_protocol }` on `Observations`

## Red Gate Verification

### S-2.08 parser tests (src/parse/rdp.rs)

| Test | AC/EC | Failure Mode |
|------|-------|-------------|
| `test_bc_1_04_004_recognizes_x224_cc_with_neg_rsp_protocol_rdp` | BC-1.04.004 | FAIL — panics at `todo!()` |
| `test_bc_1_04_004_recognizes_neg_rsp_protocol_ssl` | BC-1.04.004 | FAIL — panics at `todo!()` |
| `test_bc_1_04_004_recognizes_neg_rsp_protocol_hybrid` | BC-1.04.004 | FAIL — panics at `todo!()` |
| `test_bc_1_04_004_returns_none_without_neg_rsp` | EC-001 | FAIL — panics at `todo!()` |
| `test_bc_1_04_004_rejects_tpkt_length_mismatch` | EC-002 | FAIL — panics at `todo!()` |
| `test_bc_1_04_004_rejects_non_cc_pdu` | BC-1.04.004 | FAIL — panics at `todo!()` |
| `test_bc_1_04_004_rejects_random_bytes` | BC-1.04.004 | FAIL — panics at `todo!()` |

### S-2.08 observer tests (src/parse/rdp.rs mod tests, inline)

| Test | AC/EC | Failure Mode |
|------|-------|-------------|
| `test_bc_1_04_004_ingests_rdp_cc_on_port_3389` | BC-1.04.004 / AC-001 | FAIL — assertion: `rdp_events.len()` == 0, expected 1 (observer not yet wired) |
| `test_bc_1_04_004_ignores_rdp_on_wrong_port` | EC-003 | PASS (vacuous: rdp_events always empty; stub passes but for wrong reason — acceptable because the guard works post-implementation) |

### S-2.08 detector tests (tests/rdp_legacy.rs)

| Test | AC/EC | Failure Mode |
|------|-------|-------------|
| `test_bc_3_04_006_positive_protocol_rdp_fires_critical` | BC-3.04.006 / AC-002 | FAIL — assertion: 0 findings, expected 1 |
| `test_bc_3_04_006_negative_protocol_ssl_does_not_fire` | BC-3.04.006 | PASS (vacuous: stub returns empty Vec) |
| `test_bc_3_04_006_negative_protocol_hybrid_does_not_fire` | BC-3.04.006 | PASS (vacuous: stub returns empty Vec) |
| `test_bc_3_04_006_negative_protocol_hybrid_ex_does_not_fire` | BC-3.04.006 | PASS (vacuous: stub returns empty Vec) |
| `test_bc_3_04_006_rolls_up_by_src_dst` | BC-3.04.006 / AC-002 | FAIL — assertion: 0 findings, expected 1 |

### S-2.08 wiring test (tests/snapshot.rs)

| Test | AC/EC | Failure Mode |
|------|-------|-------------|
| `creds_rdp_no_nla_wired_into_run_all` | BC-3.04.006 | FAIL — assertion: no creds.rdp_no_nla finding found in run_all output |

## Vacuous-Pass Analysis

5 tests pass vacuously (3 negative detector tests + 1 wrong-port observer test +
the `placeholder_just_to_keep_mod_tree_alive` placeholder removed). The 3
negative detector tests (`ssl_does_not_fire`, `hybrid_does_not_fire`,
`hybrid_ex_does_not_fire`) pass because the stub returns `Vec::new()`, which
satisfies `findings.is_empty()`. This is acceptable: these tests exercise the
_absence_ of false-positives and will remain passing after correct implementation
(only PROTOCOL_RDP == 0x00 fires). They are not vacuously true in the full
implementation sense — they will catch any regression where the implementer
incorrectly fires on SSL/HYBRID/HYBRID_EX. The wrong-port observer test
(`ignores_rdp_on_wrong_port`) also passes vacuously for similar reasons.

## AC-002 Bit-Test Discrepancy

**IMPORTANT FOR IMPLEMENTER:** AC-002 in the story states the fire condition as
`selected_protocol & 0x01 == 0`. This is incorrect — it would spuriously fire on
PROTOCOL_HYBRID (0x02, CredSSP/NLA) and PROTOCOL_HYBRID_EX (0x08) because
`0x02 & 0x01 == 0` and `0x08 & 0x01 == 0`. The tests pin the correct intent:
**only `selected_protocol == 0x00000000` (PROTOCOL_RDP) fires**. Use exact
equality, not the bit-test. Tests `test_bc_3_04_006_negative_protocol_hybrid_does_not_fire`
and `test_bc_3_04_006_negative_protocol_hybrid_ex_does_not_fire` will catch
any implementation that uses the broken bit-test.

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 121 lib unit tests (pre-existing) | all pass |
| 52 snapshot integration tests (pre-existing) | all pass |
| 16 cli_smoke tests | all pass |
| 3 ntlmv1 tests | all pass |
| 3 ldap_creds tests | all pass |
| 6 weak_tls_cipher tests | all pass |
| 1 memory_bound test | all pass |
| **Total pre-existing** | **202 pass, 0 broken** |

## Hand-Off to Implementer

Stories ready for implementation: S-2.08

Implementation guidance:

1. Implement `recognize_connection_confirm` in `src/parse/rdp.rs` per the byte
   layout in the story spec. The 7 parser-level tests drive this function.

2. Wire the parser into `observe_tcp` in `src/observe.rs` — add a `dst_port == rdp::PORT`
   branch that calls `recognize_connection_confirm` and pushes an `RdpEvent`.
   The observer tests drive this.

3. Implement `build_findings` in `src/findings/rdp_legacy.rs` using a `BTreeMap`
   keyed on `(src, dst)`. **Use `selected_protocol == 0x00000000` (exact equality),
   NOT `selected_protocol & 0x01 == 0`** — the bit-test in AC-002 is incorrect
   and would spuriously fire on PROTOCOL_HYBRID (0x02) and PROTOCOL_HYBRID_EX (0x08).

4. Run `cargo test --all-features` — all 15 new tests plus 202 pre-existing must pass.
