# AC-002 — Detector (BC-3.04.004)

## Test output — 3 integration tests pass

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/ntlmv1.rs (<REPO_ROOT>/target/debug/deps/ntlmv1-2b7316d4344cf4e0)

running 3 tests
test test_bc_3_04_004_negative_ntlmv2_does_not_fire ... ok
test test_bc_3_04_004_positive_ntlmv1_emits_high_finding ... ok
test test_bc_3_04_004_rolls_up_by_src_dst ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Command: `cargo test --test ntlmv1 2>&1 | tail -10`

## Rule in the catalog

```
| [`compat.ntlmv1`](#compatntlmv1) | high | NTLMv1 authentication observed |
| [`ics.modbus_writes`](#icsmodbus_writes) | high | Modbus engineering-class commands on the wire |
| [`ics.cip_engineering`](#icscip_engineering) | high | EtherNet/IP engineering-class CIP services |
--
## `compat.ntlmv1`

**NTLMv1 authentication observed**
```

Command: `cargo run --quiet -- rules 2>&1 | grep -A2 compat.ntlmv1`

## Snapshot wiring test

```
running 1 test
test compat_ntlmv1_wired_into_run_all ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 50 filtered out; finished in 0.00s
```

Command: `cargo test --test snapshot compat_ntlmv1_wired_into_run_all 2>&1 | tail -5`
