# AC-004: Silent Without Verbose Flag

## Test: `test_bc_6_04_001_silent_when_not_verbose`

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test ai::claude_cli::tests::test_bc_6_04_001_silent_when_not_verbose ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 144 filtered out; finished in 0.00s
```

Heartbeats emit only when the `-v` flag is set OR stderr is a TTY; both conditions are OR'd together in `analyze()` so interactive terminal users always see progress even without an explicit verbose flag.
