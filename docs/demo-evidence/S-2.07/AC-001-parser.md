# AC-001 — TLS ClientHello cipher_suites parser (BC-1.04.003)

## Test output

```
$ cargo test --lib observe::tls_cipher_tests 2>&1 | tail -15
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.09s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 3 tests
test observe::tls_cipher_tests::test_bc_1_04_003_tls_client_hello_captures_cipher_suites ... ok
test observe::tls_cipher_tests::test_bc_1_04_003_empty_cipher_suites_list_does_not_panic ... ok
test observe::tls_cipher_tests::test_bc_1_04_003_truncated_payload_no_panic ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 117 filtered out; finished in 0.00s
```

## Description

The TLS observer in `src/observe.rs` extends the existing ClientHello path (which
already captured `legacy_version` for `compat.stale_tls`) to also walk the
cipher_suites list. The walk reads `session_id_len` from payload byte 43, then
computes `cs_offset = 44 + session_id_len`. A bounds-check guards against
truncated or malformed payloads — the function returns early without panicking if
the slice is too short at any step. Cipher suite codes (2 bytes each, big-endian)
are collected into a `Vec<u16>` and appended to any previously-seen suites on the
same `(src, dst, dst_port)` flow, ensuring that resumed or split handshakes
accumulate a complete picture of what the client advertised.
