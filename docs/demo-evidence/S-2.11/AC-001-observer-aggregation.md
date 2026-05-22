# AC-001: Observer Aggregation — Unit-ID Tracking (BC-1.02.009)

## Test Output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (<REPO_ROOT>/target/debug/deps/otsniff-57ecb0330ca805f6)

running 5 tests
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_ff_is_counted ... ok
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_accumulates_per_src_dst ... ok
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_0_is_counted ... ok
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_distinct_src_dst_pairs_isolated ... ok
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_dedupes_within_flow ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 129 filtered out; finished in 0.00s
```

## Description

BC-1.02.009 extends `observe.rs` to record unit IDs per `(src, dst)` Modbus flow pair.
Each `ModbusFlowSummary` now carries a `unit_ids: BTreeSet<u8>` field that accumulates
every distinct unit ID seen across all PDUs for that connection. The `BTreeSet` deduplicates
repeated unit IDs within the same flow and isolates counts between different `(src, dst)` pairs,
so two clients scanning the same server do not inflate each other's totals. Unit IDs 0
(broadcast) and 0xFF (gateway relay) are counted intentionally — both represent
suspicious targeting patterns in a sweep context. This satisfies BC-1.02.009 (renamed
from BC-1.02.006 to avoid collision with the DHCP option-walk BC introduced by S-1.05).
