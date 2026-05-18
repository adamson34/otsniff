# AC-002 — Detector finding emission (BC-3.01.005)

## Integration test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/ldap_creds.rs (<REPO_ROOT>/target/debug/deps/ldap_creds-382b31e57a3a603e)

running 3 tests
test test_bc_3_01_005_negative_post_starttls_bind_suppresses_finding ... ok
test test_bc_1_03_005_anonymous_bind_suppressed ... ok
test test_bc_3_01_005_positive_plaintext_bind_emits_critical_finding ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Command: `cargo test --test ldap_creds 2>&1 | tail -15`

## Rule catalog listing

```
| [`creds.ldap_simple_bind`](#credsldap_simple_bind) | critical | LDAP plaintext simple-bind observed |
| [`ics.modbus_writes`](#icsmodbus_writes) | high | Modbus engineering-class commands on the wire |
| [`ics.cip_engineering`](#icscip_engineering) | high | EtherNet/IP engineering-class CIP services |
--
## `creds.ldap_simple_bind`

**LDAP plaintext simple-bind observed**
```

Command: `cargo run -- rules 2>&1 | grep -A2 ldap_simple_bind`

## Snapshot regression note

All 50 snapshot tests continue to pass (confirmed via
`cargo test --test snapshot 2>&1 | tail -5`):

```
test result: ok. 50 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
```

No existing detectors were regressed by the addition of `src/findings/ldap_creds.rs`.
