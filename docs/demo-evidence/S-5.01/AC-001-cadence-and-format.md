# AC-001: Progress Emission Cadence and Format

## Unit-test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.11s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 6 tests
test progress::tests::test_bc_9_04_001_emits_after_10mb_bytes ... ok
test progress::tests::test_bc_9_04_001_finish_emits_summary_even_if_no_progress ... ok
test progress::tests::test_bc_9_04_001_emits_after_100k_packets ... ok
test progress::tests::test_bc_9_04_001_format_includes_count_and_bytes ... ok
test progress::tests::test_bc_9_04_001_rate_limited_to_2s ... ok
test progress::tests::test_bc_9_04_001_no_emission_when_verbose_false ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 134 filtered out; finished in 0.01s
```

## Cadence logic

`ProgressReporter` (in `src/progress.rs`) emits a stderr line whenever
either of two thresholds is crossed: 100,000 packets processed OR 10 MB
of raw bytes read. The two thresholds are checked per-packet in
`record_packet()`. An injectable `Clock` trait (real `SystemTime` in
production, `MockClock` in tests) gates emissions so that at most one
line appears per 2-second wall-clock window. To ensure the first
emission fires immediately rather than after a 2-second delay, the
internal `last_emitted` timestamp is initialised to
`now - RATE_LIMIT_SECS` at construction time. `finish()` always emits a
final summary regardless of the rate-limit.

## Example emission format

```
[parse] processed 100,000 packets / 6.4 MB
```

(100,000 packets × 64 bytes/packet = 6,400,000 bytes ≈ 6.4 MB, as exercised
by `test_bc_9_04_001_format_includes_count_and_bytes`.)
