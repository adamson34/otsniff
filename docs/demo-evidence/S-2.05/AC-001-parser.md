# AC-001 — LDAP Parser (BC-1.03.005)

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running unittests src/lib.rs (<REPO_ROOT>/target/debug/deps/otsniff-57ecb0330ca805f6)

running 5 tests
test parse::ldap::tests::test_bc_1_03_005_rejects_ldap_unbind ... ok
test parse::ldap::tests::test_bc_1_03_005_recognizes_anonymous_bind_empty_password ... ok
test parse::ldap::tests::test_bc_1_03_005_rejects_non_ldap_payload ... ok
test parse::ldap::tests::test_bc_1_03_005_recognizes_v3_simple_bind_with_password ... ok
test parse::ldap::tests::test_bc_1_03_005_rejects_oversized_length ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 105 filtered out; finished in 0.00s
```

Command: `cargo test --lib parse::ldap 2>&1 | tail -15`

## What `recognize_bind_request` does

`src/parse/ldap.rs::recognize_bind_request` performs a stateless BER walk over
a raw TCP payload to identify LDAP `BindRequest` PDUs. It follows RFC 4511
exactly:

1. **LDAPMessage envelope** — the outer TLV must carry universal tag `0x30`
   (SEQUENCE), which is the RFC 4511 §5.1 wire shape for every LDAPMessage.
2. **messageID** — universal tag `0x02` (INTEGER) is read and skipped; its
   value is not needed for detection purposes.
3. **protocolOp — BindRequest** — RFC 4511 §4.2 assigns `[APPLICATION 0]`
   (tag `0x60`) to BindRequest. Any other APPLICATION tag (e.g. `0x42`
   UnbindRequest, `0x63` SearchRequest) causes the function to return `None`.
4. **version INTEGER** (tag `0x02`) — extracted and stored; LDAPv3 encodes
   this as the single byte `0x03`.
5. **name LDAPDN OctetString** (tag `0x04`) — the Bind DN length is read and
   the content is skipped; the DN value is not required at the detection layer.
6. **AuthenticationChoice** — RFC 4511 §4.2 defines two choices: `simple [0]
   IMPLICIT OctetString` (tag `0x80`) and `sasl [3] SaslCredentials` (tag
   `0xa3`). Only tag `0x80` is accepted. An empty password (`pw_len == 0`)
   sets `anonymous: true` per EC-003. The `used_starttls` field is always
   `false` here — it is flow-level context supplied by the caller in
   `observe.rs` after consulting the per-flow STARTTLS state map.

The function uses only short-form BER lengths (< 128). Oversized or malformed
lengths cause an early `None` return without panicking.
