# EC-002 — MessageType Validation

## Random bytes rejected

```
running 1 test
test observe::ntlm_tests::test_bc_1_03_006_rejects_random_bytes ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 116 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_1_03_006_rejects_random_bytes 2>&1 | tail -5`

## CHALLENGE (MessageType=2) rejected

```
running 1 test
test observe::ntlm_tests::test_bc_1_03_006_rejects_challenge_messagetype ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 116 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_1_03_006_rejects_challenge_messagetype 2>&1 | tail -5`

## AUTHENTICATE (MessageType=3) rejected

```
running 1 test
test observe::ntlm_tests::test_bc_1_03_006_rejects_authenticate_messagetype ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 116 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_1_03_006_rejects_authenticate_messagetype 2>&1 | tail -5`

## Truncated payload rejected

```
running 1 test
test observe::ntlm_tests::test_bc_1_03_006_rejects_truncated_payload ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 116 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_1_03_006_rejects_truncated_payload 2>&1 | tail -5`

## Note

The parser only accepts `MessageType = 1` (NEGOTIATE); a payload carrying the
`NTLMSSP\0` signature but with MessageType 2 (CHALLENGE) or 3 (AUTHENTICATE)
is rejected — no `NtlmEvent` is emitted, preventing false positives from
server-side or authentication-completion messages that happen to contain the
same 8-byte signature prefix.
