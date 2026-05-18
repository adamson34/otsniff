# AC-001 — NTLM Parser (BC-1.03.006)

## Test output — 6 parser unit tests

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.11s
     Running unittests src/lib.rs (<REPO_ROOT>/target/debug/deps/otsniff-57ecb0330ca805f6)

running 6 tests
test observe::ntlm_tests::test_bc_1_03_006_rejects_authenticate_messagetype ... ok
test observe::ntlm_tests::test_bc_1_03_006_recognizes_ntlmv2_negotiate ... ok
test observe::ntlm_tests::test_bc_1_03_006_recognizes_ntlmv1_negotiate ... ok
test observe::ntlm_tests::test_bc_1_03_006_rejects_challenge_messagetype ... ok
test observe::ntlm_tests::test_bc_1_03_006_rejects_random_bytes ... ok
test observe::ntlm_tests::test_bc_1_03_006_rejects_truncated_payload ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 111 filtered out; finished in 0.00s
```

Command: `cargo test --lib observe::ntlm_tests 2>&1 | tail -15`

## Test output — observer ingests NTLMv1 on SMB port 445

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (<REPO_ROOT>/target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test observe::tests::test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 116 filtered out; finished in 0.00s
```

Command: `cargo test --lib observe::tests::test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445 2>&1 | tail -10`

## What the NTLM recognizer does

`observe.rs` scans incoming TCP payloads using `windows(8)` to locate the
8-byte NTLMSSP signature (`4e 54 4c 4d 53 53 50 00`, i.e. `"NTLMSSP\0"`).
Once the signature is found at offset `i`, the recognizer reads the next 4
bytes at `i+8` as a little-endian u32 `MessageType`; only `MessageType = 1`
(NEGOTIATE) is accepted — CHALLENGE (2) and AUTHENTICATE (3) are rejected
with `None`. With a confirmed NEGOTIATE, the flags field is read from bytes
`i+12..i+16` as a u32 LE. Two bits drive the version classification: bit
`0x00000200` (`NTLMSSP_NEGOTIATE_NTLM`, the "NTLM" flag) signals that
NTLMv1-class hashing is offered; bit `0x00080000`
(`NTLMSSP_NEGOTIATE_NTLM2_KEY`, also known as Extended Session Security) is
the NTLMv2 upgrade indicator. If the NTLM bit is set and NTLM2_KEY is unset,
the event is classified `NtlmVersion::V1`; if NTLM2_KEY is set it is `V2`.
Only events that pass all checks reach `Observer::ntlm_events`.
