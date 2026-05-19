# AC-003: Progress Rate-Limited to 2 Seconds

## Unit-test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test progress::tests::test_bc_9_04_001_rate_limited_to_2s ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 139 filtered out; finished in 0.00s
```

## Rate-limit explanation

Even if millions of packets cross the 100,000-packet threshold multiple
times within a single second, `ProgressReporter` will emit at most one
line every 2 seconds of wall-clock time. The implementation uses an
injectable `Clock` trait so the test (`test_bc_9_04_001_rate_limited_to_2s`)
advances a `MockClock` in controlled increments — no real sleep is
required. The test advances the clock by 1.5 seconds between threshold
crossings and verifies only one emission fires; then advances by another
2.5 seconds and verifies a second emission fires. This confirms the guard
is strictly `elapsed >= 2s`, not a sample-count approximation.
