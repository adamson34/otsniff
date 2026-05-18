# EC-001 — GREASE values not flagged

## Test output

```
$ cargo test --test weak_tls_cipher test_bc_3_04_005_grease 2>&1 | tail -10
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/weak_tls_cipher.rs (target/debug/deps/weak_tls_cipher-7269d65809e37448)

running 1 test
test test_bc_3_04_005_grease_values_skipped ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
```

## Note

GREASE values (0x?A?A pattern per RFC 8701) are not in the weak-cipher list, so they are naturally skipped by `is_weak()`.
