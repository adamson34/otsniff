# AC-004: Memory-bound test

## Test run output

```
running 1 test
test test_bc_1_03_007_cred_events_bounded_under_1m_duplicates ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s
```

`cargo test --test memory_bound` passes. The test asserts peak heap stays
below 100 MB when ingesting a synthetic Telnet-heavy fixture, satisfying
AC-004 and verifying the S-2.02 memory invariant continues to hold.
