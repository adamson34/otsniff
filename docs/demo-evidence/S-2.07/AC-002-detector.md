# AC-002 — `compat.weak_tls_cipher` detector (BC-3.04.005)

## Integration tests (6 tests)

```
$ cargo test --test weak_tls_cipher 2>&1 | tail -20
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/weak_tls_cipher.rs (target/debug/deps/weak_tls_cipher-7269d65809e37448)

running 6 tests
test test_bc_3_04_005_negative_only_strong_ciphers_does_not_fire ... ok
test test_bc_3_04_005_positive_rc4_emits_medium_finding ... ok
test test_bc_3_04_005_rolls_up_by_src_dst ... ok
test test_bc_3_04_005_grease_values_skipped ... ok
test test_bc_3_04_005_legacy_version_and_weak_cipher_fire_both_findings ... ok
test test_bc_3_04_005_positive_des_3des_null_each_fire ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Rule catalog

```
$ cargo run --quiet -- rules 2>&1 | grep -A3 weak_tls_cipher
| [`compat.weak_tls_cipher`](#compatweak_tls_cipher) | medium | Weak TLS cipher suites advertised (RC4 / DES / 3DES / NULL) |
| [`egress.ot_to_internet`](#egressot_to_internet) | critical | Internet-bound traffic from OT subnets |
| [`boundary.dns_resolver`](#boundarydns_resolver) | medium | DNS queries from OT to an out-of-zone resolver |
| [`boundary.ntp_external`](#boundaryntp_external) | medium | OT host syncing time to public NTP |
--
## `compat.weak_tls_cipher`

**Weak TLS cipher suites advertised (RC4 / DES / 3DES / NULL)**
```

## Snapshot wiring test

```
$ cargo test --test snapshot compat_weak_tls_cipher_wired_into_run_all 2>&1 | tail -5
running 1 test
test compat_weak_tls_cipher_wired_into_run_all ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 51 filtered out; finished in 0.00s
```

## Weak cipher codes detected

| Code   | Cipher Suite Name                     |
|--------|---------------------------------------|
| 0x0001 | TLS_RSA_WITH_NULL_MD5                 |
| 0x0002 | TLS_RSA_WITH_NULL_SHA                 |
| 0x0004 | TLS_RSA_WITH_RC4_128_MD5              |
| 0x0005 | TLS_RSA_WITH_RC4_128_SHA              |
| 0x0009 | TLS_RSA_WITH_DES_CBC_SHA              |
| 0x000A | TLS_RSA_WITH_3DES_EDE_CBC_SHA         |
