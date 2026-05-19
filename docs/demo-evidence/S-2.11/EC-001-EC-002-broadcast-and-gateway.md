# EC-001 + EC-002: Broadcast (Unit ID 0) and Gateway (Unit ID 0xFF)

## EC-001: Unit ID 0 (broadcast) is counted

```
running 1 test
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_0_is_counted ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 133 filtered out; finished in 0.00s
```

## EC-002: Unit ID 0xFF (gateway relay) is counted

```
running 1 test
test observe::modbus_unit_id_tests::test_bc_1_02_009_unit_id_ff_is_counted ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 133 filtered out; finished in 0.00s
```

## Note

Both unit IDs are intentionally counted: broadcasting to unit ID 0 and probing
the gateway relay at unit ID 0xFF are themselves suspicious patterns indicative
of discovery or sweep activity, not normal operational traffic.
