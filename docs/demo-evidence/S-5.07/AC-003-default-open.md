# AC-003: Default state is open

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/snapshot.rs (target/debug/deps/snapshot-2ad6c088c6f4c115)

running 1 test
test test_bc_8_01_005_default_state_is_open ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s
```

All `class="finding sev-..."` elements render with the `open` attribute. Zero `<details class="finding ...">` without `open`.
