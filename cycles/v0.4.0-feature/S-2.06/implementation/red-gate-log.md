---
document_type: red-gate-log
level: ops
version: "1.0"
status: complete
producer: test-writer
timestamp: 2026-05-18T21:00:00Z
phase: 3
inputs:
  - .factory/stories/S-2.06-compat-ntlmv1.md
  - src/observe.rs
  - src/findings/ntlmv1.rs
  - src/findings/mod.rs
input-hash: "[md5]"
traces_to: "BC-1.03.006, BC-3.04.004"
stub_architect_agent: "f366f07"
stub_compile_verified: true
test_writer_agent: "claude-sonnet-4-6"
red_gate_verified: true
---

# Red Gate Log: S-2.06 — compat.ntlmv1 NTLMv1 authentication detection

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|-------------|-----------------|------|
| S-2.06 | 10 new tests (7 unit, 2 integration, 1 snapshot) | Yes (9/10 fail; 1 vacuous-pass per design) | PASSED |

## Stubs Created

### S-2.06: NTLMv1 detection

- `pub(crate) struct NtlmNegotiateRecognized { pub version: NtlmVersion }` — result type for NTLM NEGOTIATE parser; lives in `src/observe.rs`
- `pub(crate) fn recognize_ntlm_negotiate(_payload: &[u8]) -> Option<NtlmNegotiateRecognized>` — stub body is `todo!("S-2.06 Step 4: implement NTLM NEGOTIATE recognizer")`; lives in `src/observe.rs`

## Red Gate Verification

### S-2.06 — Parser unit tests (`src/observe.rs`, `mod ntlm_tests`)

All 6 parser unit tests panic with `not yet implemented: S-2.06 Step 4: implement NTLM NEGOTIATE recognizer`:

- BC-1.03.006: `test_bc_1_03_006_recognizes_ntlmv1_negotiate` — FAIL (panic: todo!())
- BC-1.03.006: `test_bc_1_03_006_recognizes_ntlmv2_negotiate` — FAIL (panic: todo!())
- EC-002: `test_bc_1_03_006_rejects_random_bytes` — FAIL (panic: todo!())
- EC-002: `test_bc_1_03_006_rejects_challenge_messagetype` — FAIL (panic: todo!())
- EC-002: `test_bc_1_03_006_rejects_authenticate_messagetype` — FAIL (panic: todo!())
- defensive: `test_bc_1_03_006_rejects_truncated_payload` — FAIL (panic: todo!())

### S-2.06 — Observer integration test (`src/observe.rs`, `mod tests`)

- AC-001 (BC-1.03.006): `test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445` — FAIL
  ```
  assertion `left == right` failed: AC-001: observer must append one NtlmEvent for an NTLMSSP NEGOTIATE on tcp/445
    left: 0
   right: 1
  ```

### S-2.06 — Detector integration tests (`tests/ntlmv1.rs`)

- AC-002 (BC-3.04.004): `test_bc_3_04_004_positive_ntlmv1_emits_high_finding` — FAIL
  ```
  assertion `left == right` failed: AC-002: must fire exactly one finding when a NTLMv1 event is observed
    left: 0
   right: 1
  ```
- EC-001: `test_bc_3_04_004_negative_ntlmv2_does_not_fire` — PASS (vacuous: build_findings returns empty for all inputs; acceptable per story design — flips to meaningful regression once positive passes)
- AC-002 rollup: `test_bc_3_04_004_rolls_up_by_src_dst` — FAIL
  ```
  assertion `left == right` failed: AC-002 rollup: two V1 events from the same (src, dst) must collapse to one finding
    left: 0
   right: 1
  ```

### S-2.06 — Snapshot wiring test (`tests/snapshot.rs`)

- BC-3.04.004 wiring: `compat_ntlmv1_wired_into_run_all` — FAIL
  ```
  run_all must include compat.ntlmv1 when ntlm_events contains a V1 event
  ```

## Verbatim cargo test output (lib crate)

```
running 117 tests
...
test observe::ntlm_tests::test_bc_1_03_006_recognizes_ntlmv1_negotiate ... FAILED
test observe::ntlm_tests::test_bc_1_03_006_rejects_challenge_messagetype ... FAILED
test observe::ntlm_tests::test_bc_1_03_006_recognizes_ntlmv2_negotiate ... FAILED
test observe::ntlm_tests::test_bc_1_03_006_rejects_authenticate_messagetype ... FAILED
test observe::ntlm_tests::test_bc_1_03_006_rejects_random_bytes ... FAILED
test observe::ntlm_tests::test_bc_1_03_006_rejects_truncated_payload ... FAILED
...
test observe::tests::test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445 ... FAILED
...

failures:
    observe::ntlm_tests::test_bc_1_03_006_recognizes_ntlmv1_negotiate
    observe::ntlm_tests::test_bc_1_03_006_recognizes_ntlmv2_negotiate
    observe::ntlm_tests::test_bc_1_03_006_rejects_authenticate_messagetype
    observe::ntlm_tests::test_bc_1_03_006_rejects_challenge_messagetype
    observe::ntlm_tests::test_bc_1_03_006_rejects_random_bytes
    observe::ntlm_tests::test_bc_1_03_006_rejects_truncated_payload
    observe::tests::test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445

test result: FAILED. 110 passed; 7 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 110 pre-existing lib unit tests | all pass |
| 50 pre-existing snapshot integration tests | all pass |
| 1 ldap_creds integration tests | all pass |
| 1 memory_bound integration tests | all pass |
| Total: ~180 pre-existing tests | all pass |

## Hand-Off to Implementer

Stories ready for implementation: S-2.06

Implementation guidance:
1. Implement `recognize_ntlm_negotiate` in `src/observe.rs` — signature already fixed; remove `todo!()` body. The function must check bytes 0-7 for `b"NTLMSSP\0"`, bytes 8-11 for `[0x01, 0x00, 0x00, 0x00]` (NEGOTIATE type), and decode bytes 12-15 as LE u32 flags. Bit 19 (0x00080000) set → V2; bit 9 (0x00000200) set and bit 19 unset → V1.
2. Wire `recognize_ntlm_negotiate` into `observe_tcp` — scan the full payload with `find_subseq` for `b"NTLMSSP\0"`, call the recognizer on the found offset, push `NtlmEvent` into `obs.ntlm_events`. Port filter: 445, 139 (SMB), 80/8080 after checking for HTTP NTLM header, 135 (RPC). The test `test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445` only tests port 445 — start there.
3. Implement `build_findings` in `src/findings/ntlmv1.rs` — roll up by `(src, dst)` using `BTreeMap`, emit one `Finding { id: "compat.ntlmv1", severity: Severity::High, ... }` per pair. Mirror the ldap_creds detector pattern exactly.
4. Note: The dead_code warnings on `NtlmNegotiateRecognized` and `recognize_ntlm_negotiate` will vanish once the implementer calls them from `observe_tcp`.
