# EC-002: Error Propagation

## Test: `test_bc_6_04_001_propagates_task_error`

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test ai::claude_cli::tests::test_bc_6_04_001_propagates_task_error ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 144 filtered out; finished in 0.00s
```

Task-thread errors propagate through `run_with_heartbeat`'s return value; the heartbeat thread joins cleanly before the error is surfaced to the caller.
