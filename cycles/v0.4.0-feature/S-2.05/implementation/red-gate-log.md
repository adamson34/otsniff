---
document_type: red-gate-log
level: ops
version: "1.0"
status: complete
producer: test-writer
timestamp: 2026-05-18T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-2.05-creds-ldap-simple-bind.md
  - src/parse/ldap.rs (stub)
  - src/observe.rs (stub)
  - src/findings/ldap_creds.rs (stub)
traces_to: BC-1.03.005, BC-3.01.005
stub_architect_agent: "[e8b0943]"
stub_compile_verified: true
test_writer_agent: "[6cfd694]"
red_gate_verified: true
---

# Red Gate Log: S-2.05 — creds.ldap_simple_bind

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-2.05 | 10 | YES | PASSED (correctly red) |

## Stubs Created (commit e8b0943)

- `src/parse/ldap.rs` — `pub fn recognize_bind_request(_bytes: &[u8]) -> Option<LdapBindRecognized>` — `todo!(...)`
- `src/findings/ldap_creds.rs` — `pub fn build_findings(_obs: &Observations) -> Vec<Finding>` — `todo!(...)`
- `src/observe.rs` — `pub struct LdapBindEvent` + `pub ldap_bind_events: Vec<LdapBindEvent>` on `Observations`

## Schema Extension (test-driven)

`anonymous: bool` added to `LdapBindEvent` in `src/observe.rs` as part of
this test-writing step. Required by EC-003: the suppression test must be able
to mark a bind event as anonymous to verify the finding layer suppresses it.
This is a test-driven schema extension — the stub had only the fields
declared in the AC-001 narrative; EC-003 requires the anonymity signal.

## Red Gate Verification

All 10 new tests fail before any implementation.

### S-2.05: Parser tests (src/parse/ldap.rs)

- AC-001 (BC-1.03.005): `test_BC_1_03_005_recognizes_v3_simple_bind_with_password` — FAIL
  ```
  panicked at src/parse/ldap.rs:42:5:
  not yet implemented: S-2.05: implement BER walk for LDAPMessage → ProtocolOp → BindRequest
  ```
- AC-001/EC-003 (BC-1.03.005): `test_BC_1_03_005_recognizes_anonymous_bind_empty_password` — FAIL
  ```
  panicked at src/parse/ldap.rs:42:5:
  not yet implemented: S-2.05: implement BER walk for LDAPMessage → ProtocolOp → BindRequest
  ```
- Negative (BC-1.03.005): `test_BC_1_03_005_rejects_non_ldap_payload` — FAIL
  ```
  panicked at src/parse/ldap.rs:42:5:
  not yet implemented: S-2.05: implement BER walk for LDAPMessage → ProtocolOp → BindRequest
  ```
- Negative (BC-1.03.005): `test_BC_1_03_005_rejects_ldap_unbind` — FAIL
  ```
  panicked at src/parse/ldap.rs:42:5:
  not yet implemented: S-2.05: implement BER walk for LDAPMessage → ProtocolOp → BindRequest
  ```
- Defensive (BC-1.03.005): `test_BC_1_03_005_rejects_oversized_length` — FAIL
  ```
  panicked at src/parse/ldap.rs:42:5:
  not yet implemented: S-2.05: implement BER walk for LDAPMessage → ProtocolOp → BindRequest
  ```

### S-2.05: Observer tests (src/observe.rs)

- AC-001 (BC-1.03.005): `test_BC_1_03_005_ingests_ldap_bind_on_port_389` — FAIL
  ```
  panicked at src/observe.rs:1029:9:
  assertion `left == right` failed: AC-001: observer must append one LdapBindEvent for a tcp/389 BindRequest
    left: 0
   right: 1
  ```
- EC-001: `test_BC_1_03_005_ingests_ldap_bind_on_port_3268` — FAIL
  ```
  panicked at src/observe.rs:1051:9:
  assertion `left == right` failed: EC-001: observer must append one LdapBindEvent for a tcp/3268 BindRequest
    left: 0
   right: 1
  ```

### S-2.05: Detector tests (tests/ldap_creds.rs)

- AC-002 (BC-3.01.005): `test_BC_3_01_005_positive_plaintext_bind_emits_critical_finding` — FAIL
  ```
  panicked at src/findings/ldap_creds.rs:29:5:
  not yet implemented: S-2.05: LDAP creds detector landing in step 4
  ```
- AC-003 negative: `test_BC_3_01_005_negative_post_starttls_bind_suppresses_finding` — FAIL
  ```
  panicked at src/findings/ldap_creds.rs:29:5:
  not yet implemented: S-2.05: LDAP creds detector landing in step 4
  ```
- EC-003: `test_BC_1_03_005_anonymous_bind_suppressed` — FAIL
  ```
  panicked at src/findings/ldap_creds.rs:29:5:
  not yet implemented: S-2.05: LDAP creds detector landing in step 4
  ```

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 103 lib unit tests (pre-S-2.05) | all pass |
| 16 cli_smoke integration tests | all pass |
| 1 memory_bound integration test | pass |
| 22 snapshot tests not exercising run_all | pass |
| 28 snapshot tests exercising run_all | pre-existing FAIL (todo!() in stub commit e8b0943 — not caused by test-writer changes) |

Note: The 28 snapshot failures are pre-existing and were present in stub commit
`e8b0943` before any test-writer changes. They fail because `run_all` calls
`ldap_creds::build_findings` which is `todo!()`. This is expected — the
implementer must resolve them.

## Hand-Off to Implementer

- Stories ready for implementation: S-2.05
- Make each test pass in this order:
  1. `recognize_bind_request` in `src/parse/ldap.rs` (unblocks 5 parser tests)
  2. Wire `recognize_bind_request` into `observe_tcp` in `src/observe.rs` for ports 389 and 3268 (unblocks 2 observer tests)
  3. Implement `build_findings` in `src/findings/ldap_creds.rs` with STARTTLS + anonymous suppression (unblocks 3 integration tests + 28 snapshot tests)
- Key BER structure: outer 0x30 SEQUENCE → messageID 0x02 → BindRequest 0x60 → version 0x02 → DN 0x04 → SimpleAuth 0x80
- RFC 4511 §4.2 is the normative reference for the wire format
- `anonymous` is true when both DN length and password length are 0
- Observer tests use `Observer::observations()` accessor (not `observer.finish()`) to avoid consuming the observer
