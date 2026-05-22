# AC-001 — RDP Parser (BC-1.04.004)

## Test Output

```
$ cargo test --lib parse::rdp 2>&1 | tail -20

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.38s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 9 tests
test parse::rdp::tests::test_bc_1_04_004_rejects_random_bytes ... ok
test parse::rdp::tests::test_bc_1_04_004_returns_none_without_neg_rsp ... ok
test parse::rdp::tests::test_bc_1_04_004_recognizes_neg_rsp_protocol_ssl ... ok
test parse::rdp::tests::test_bc_1_04_004_recognizes_neg_rsp_protocol_hybrid ... ok
test parse::rdp::tests::test_bc_1_04_004_recognizes_x224_cc_with_neg_rsp_protocol_rdp ... ok
test parse::rdp::tests::test_bc_1_04_004_rejects_tpkt_length_mismatch ... ok
test parse::rdp::tests::test_bc_1_04_004_rejects_non_cc_pdu ... ok
test parse::rdp::tests::test_bc_1_04_004_ignores_rdp_on_wrong_port ... ok
test parse::rdp::tests::test_bc_1_04_004_ingests_rdp_cc_on_port_3389 ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 120 filtered out; finished in 0.00s
```

## Description

The parser walks an RDP X.224 Connection Confirm packet in two stages. The outer
framing is TPKT (RFC 1006): version 3, reserved byte, then a big-endian u16 length
that must exactly match the payload byte count — any mismatch is rejected and
`None` is returned. Immediately following is the X.224 header; the PDU type byte
must be `0xD0` (Connection Confirm) or the packet is silently ignored.

The optional `RDP_NEG_RSP` block starts at byte offset 11 (after the 4-byte TPKT
header and 7-byte X.224 CC fixed part). Its `type` field must be `0x02` to be
recognised; if absent or of a different type the parser returns `None` rather than
firing. The `selectedProtocol` field at offset 15 is read as a little-endian u32
(RDP spec §2.2.1.2.1), while the surrounding TPKT length is big-endian — the
parser handles both endiannesses explicitly. Recognition is gated on tcp/3389; the
same byte pattern on any other port is ignored.
