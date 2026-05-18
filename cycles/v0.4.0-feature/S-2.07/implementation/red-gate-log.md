---
document_type: red-gate-log
level: ops
version: "1.0"
status: passed
producer: test-writer
timestamp: 2026-05-18T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-2.07-compat-weak-tls-cipher.md
input-hash: "[md5]"
traces_to: "BC-1.04.003, BC-3.04.005"
stub_architect_agent: "673f0e6"
stub_compile_verified: true
test_writer_agent: "[current session]"
red_gate_verified: true
---

# Red Gate Log: S-2.07 — compat.weak_tls_cipher

## Summary
| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-2.07 | 10 | Yes (7 fail, 3 vacuous-pass by design) | PASSED |

## Stubs Created (by stub commit 673f0e6)
- `fn build_findings(_obs: &Observations) -> Vec<Finding>` in `src/findings/weak_tls_cipher.rs` — returns `Vec::new()`
- `pub tls_cipher_suites: HashMap<(IpAddr, IpAddr, u16), Vec<u16>>` in `Observations` — always empty

## Red Gate Verification

### S-2.07

**Parser tests (src/observe.rs — mod tls_cipher_tests)**

- AC-001 (BC-1.04.003): `test_bc_1_04_003_tls_client_hello_captures_cipher_suites` — FAIL (assertion: tls_cipher_suites entry absent, observer not yet extended)
- AC-001 (BC-1.04.003): `test_bc_1_04_003_empty_cipher_suites_list_does_not_panic` — PASS (vacuous: no-panic test, acceptable per story design — stub never panics)
- AC-001 (BC-1.04.003): `test_bc_1_04_003_truncated_payload_no_panic` — PASS (vacuous: no-panic test, stub never panics)

**Detector tests (tests/weak_tls_cipher.rs)**

- AC-002 (BC-3.04.005): `test_bc_3_04_005_positive_rc4_emits_medium_finding` — FAIL (assertion: 0 findings, stub returns empty Vec)
- AC-002 (BC-3.04.005): `test_bc_3_04_005_positive_des_3des_null_each_fire` — FAIL (assertion: 0 findings for DES/3DES/NULL)
- AC-002 (BC-3.04.005): `test_bc_3_04_005_negative_only_strong_ciphers_does_not_fire` — PASS (vacuous: negative test, stub's empty Vec is correct for no-fire case)
- AC-002 (BC-3.04.005): `test_bc_3_04_005_rolls_up_by_src_dst` — FAIL (assertion: 0 findings, rollup not implemented)
- EC-001 (BC-3.04.005): `test_bc_3_04_005_grease_values_skipped` — FAIL (assertion: expected 1 finding for RC4 alongside GREASE, got 0)
- AC-003 (BC-3.04.005): `test_bc_3_04_005_legacy_version_and_weak_cipher_fire_both_findings` — FAIL (rule_ids has stale_tls but not weak_tls_cipher)

**Snapshot wiring test (tests/snapshot.rs)**

- AC-002 (BC-3.04.005): `compat_weak_tls_cipher_wired_into_run_all` — FAIL (assertion: finding absent from run_all output)

## Regression Check
| Existing Tests | Status |
|---------------|--------|
| 119 lib unit tests (pre-existing) | all pass |
| 16 cli_smoke integration tests | all pass |
| 3 ldap_creds integration tests | all pass |
| 1 memory_bound integration test | all pass |
| 3 ntlmv1 integration tests | all pass |
| 51 snapshot integration tests (pre-existing) | all pass |
| **191 total pre-existing** | **all pass — no regressions** |

## Hand-Off to Implementer

Stories ready for implementation: S-2.07

Implementation guidance:

1. **Step 4 (observer extension):** Extend the TLS ClientHello block in
   `src/observe.rs::observe_tcp` (around line 618) to walk past the 32-byte
   Random field and session_id (variable length, prefixed by a 1-byte length)
   then read the cipher_suites_length (big-endian u16) and collect each
   big-endian u16 cipher code into a `Vec<u16>`, then `extend` (or insert)
   into `obs.tls_cipher_suites[(src_ip, dst_ip, dst_port)]`. The session_id
   is at offset 43 (after the 9-byte TLS record+handshake header and 32-byte
   random); its length is payload[43]. Bounds-check every slice.

2. **Step 3 (detector):** Implement `build_findings` in
   `src/findings/weak_tls_cipher.rs`. Iterate `obs.tls_cipher_suites`, group
   by `(src, dst)` (drop port for rollup per AC-002), collect all weak codes
   (0x0001, 0x0002, 0x0004, 0x0005, 0x0009, 0x000A), skip GREASE (0x?A?A
   pattern), emit one `Finding` per `(src, dst)` pair listing offending codes.

3. **Notable observer quirk:** The existing TLS block only fires when
   `payload.len() >= 11 && payload[0] == 0x16 && payload[5] == 0x01`. The
   cipher_suites data starts at offset 44 + session_id_len, so a minimum
   safe payload size before attempting cipher_suites decode is around 48
   bytes. Defensive: if the payload is shorter, skip silently (don't panic).

4. **GREASE detection:** A value is GREASE iff both bytes equal and the low
   nibble of each byte is 0xA: `v & 0x0F0F == 0x0A0A && (v >> 8) == (v & 0xFF)`.
   Or more simply: RFC 8701 GREASE values are exactly the set
   {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}.
   None of these overlap with the weak-cipher list, so a simple lookup in
   the weak set is sufficient — GREASE will never accidentally fire.
   The GREASE test pins this non-interference requirement explicitly.

5. **Clippy:** Both `src/observe.rs` test helpers and `tests/weak_tls_cipher.rs`
   pass `cargo clippy --all-targets -- -D warnings` clean (exit 0).
