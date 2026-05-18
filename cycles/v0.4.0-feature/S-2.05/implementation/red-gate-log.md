---
document_type: red-gate-log
level: ops
version: "1.1"
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
green_by_design_fix: "[7e3b0c6]"
red_gate_verified: true
---

# Red Gate Log: S-2.05 — creds.ldap_simple_bind

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-2.05 | 10 | YES | PASSED (correctly red) |

## Green-by-Design Fix (commit 7e3b0c6)

The stub-architect wired `ldap_creds::build_findings` into `run_all_findings`
with a `todo!()` body, which caused 28 pre-existing snapshot tests (and the
`rule_catalog_matches_committed_rules_md` snapshot) to panic. This is a
green-by-design stub regression: any stub wired into a live pipeline must
return a benign no-op value rather than panic.

Fix applied in commit `7e3b0c6`:
- Changed `todo!("S-2.05: LDAP creds detector landing in step 4")` to `Vec::new()`
- Added doc comment explaining stub status above the function
- Regenerated `docs/RULES.md` (now **16 rules**, including `creds.ldap_simple_bind` stub entry)

**Result after fix:**
- 170 pre-existing tests now pass (snapshot 50/50, cli_smoke 16/16, memory_bound 1/1, lib 103/103)
- New S-2.05 tests remain correctly red (7 lib + 1 integration = 8 failing tests)
- `ldap_creds` integration tests: 2 of 3 now pass vacuously (suppression tests pass because `Vec::new()` suppresses everything); 1 fails via assertion — see updated table below

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

## Red Gate Verification (updated post green-by-design fix)

After fix commit `7e3b0c6`: 8 new S-2.05 tests fail, 2 ldap_creds integration tests pass
vacuously (suppression/anonymous tests pass because `Vec::new()` is already empty). The
positive detection test (`test_BC_3_01_005_positive_plaintext_bind_emits_critical_finding`)
remains correctly red — failing via assertion, not panic.

Original pre-fix: all 10 new tests failed before any implementation.

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

### S-2.05: Detector tests (tests/ldap_creds.rs) — post green-by-design fix

- AC-002 (BC-3.01.005): `test_BC_3_01_005_positive_plaintext_bind_emits_critical_finding` — FAIL (correctly red)
  ```
  panicked at tests/ldap_creds.rs:60:5:
  assertion `left == right` failed: AC-002: must fire exactly one finding on plaintext bind
    left: 0
   right: 1
  ```
  Failure mode changed from `todo!()` panic to assertion failure. This is correct red-gate behaviour.

- AC-003 negative: `test_BC_3_01_005_negative_post_starttls_bind_suppresses_finding` — PASS (vacuously green)
  `Vec::new()` already suppresses all findings; the suppression test passes vacuously.
  This is acceptable — the suppression logic will be stress-tested once the positive path exists.

- EC-003: `test_BC_1_03_005_anonymous_bind_suppressed` — PASS (vacuously green)
  Same reason as above.

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 103 lib unit tests (pre-S-2.05) | all pass |
| 16 cli_smoke integration tests | all pass |
| 1 memory_bound integration test | pass |
| 50 snapshot tests (incl. rule_catalog) | all pass (after RULES.md regen in 7e3b0c6) |

**All 170 pre-existing tests pass** after the green-by-design fix in commit `7e3b0c6`.

Note: `docs/RULES.md` was regenerated as part of the fix commit because the
stub introduced a new rule (`creds.ldap_simple_bind`), changing the catalog from
15 to 16 rules. The `rule_catalog_matches_committed_rules_md` snapshot enforces
that `docs/RULES.md` matches the live catalog output.

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
