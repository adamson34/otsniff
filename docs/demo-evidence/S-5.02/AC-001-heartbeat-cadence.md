# AC-001: Heartbeat Cadence

## Test: `test_bc_6_04_001_emits_heartbeat_every_3s`

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.10s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test ai::claude_cli::tests::test_bc_6_04_001_emits_heartbeat_every_3s ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 144 filtered out; finished in 0.25s
```

## Test: `test_bc_6_04_001_summary_includes_duration_and_byte_count`

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test ai::claude_cli::tests::test_bc_6_04_001_summary_includes_duration_and_byte_count ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 144 filtered out; finished in 0.00s
```

## Description

`ClaudeCliProvider::analyze` spawns the `claude -p` subprocess on a background
thread and drives a heartbeat loop on the calling thread via the injected `Clock`
trait. Every 3 seconds of wall-clock time while the subprocess is alive the
implementation writes `[Ns] claude still working...` to the configured writer.
When the background thread joins, a single summary line is emitted in the format:

```
done in 11.4s, 4127 bytes response
```

The `Clock` injection (using `MockClock` in tests) lets the test advance time
in discrete steps without any real sleeping, making the cadence assertions
deterministic and fast.
