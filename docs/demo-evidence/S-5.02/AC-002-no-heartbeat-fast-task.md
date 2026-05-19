# AC-002: No Heartbeat for Fast Task

## Test: `test_bc_6_04_001_no_heartbeat_for_fast_task`

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test ai::claude_cli::tests::test_bc_6_04_001_no_heartbeat_for_fast_task ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 144 filtered out; finished in 0.00s
```

Tasks completing before the first 3-second tick fires emit only the final summary line; no `still working` lines appear in the output.
