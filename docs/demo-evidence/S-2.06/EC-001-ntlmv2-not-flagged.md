# EC-001 — NTLMv2 Not Flagged

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/ntlmv1.rs (<REPO_ROOT>/target/debug/deps/ntlmv1-2b7316d4344cf4e0)

running 1 test
test test_bc_3_04_004_negative_ntlmv2_does_not_fire ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

Command: `cargo test --test ntlmv1 test_bc_3_04_004_negative_ntlmv2_does_not_fire 2>&1 | tail -10`

## Note

When the `NTLMSSP_NEGOTIATE_NTLM2_KEY` flag (`0x00080000`) is present in the
NEGOTIATE message flags field, the recognizer classifies the event as
`NtlmVersion::V2`; the `compat.ntlmv1` detector only iterates over V1 events
and ignores V2, so no finding is emitted — the NTLMv2 session is silently
passed through without a false positive.
