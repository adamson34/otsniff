# AC-003 — Sibling finding alongside `compat.stale_tls`

## Test output

```
$ cargo test --test weak_tls_cipher test_bc_3_04_005_legacy_version_and_weak_cipher 2>&1 | tail -10
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/weak_tls_cipher.rs (target/debug/deps/weak_tls_cipher-7269d65809e37448)

running 1 test
test test_bc_3_04_005_legacy_version_and_weak_cipher_fire_both_findings ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s
```

## Note

`compat.weak_tls_cipher` fires alongside `compat.stale_tls` — neither suppresses the other.
