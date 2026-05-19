# EC-001 / EC-002 / EC-003 — Parser Defenses

## EC-001 — RDP_NEG_RSP Missing (Returns None, Does Not Fire)

```
$ cargo test --lib test_bc_1_04_004_returns_none_without_neg_rsp 2>&1 | tail -5

running 1 test
test parse::rdp::tests::test_bc_1_04_004_returns_none_without_neg_rsp ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 128 filtered out; finished in 0.00s
```

## EC-002 — TPKT Length Mismatch (Rejected)

```
$ cargo test --lib test_bc_1_04_004_rejects_tpkt_length_mismatch 2>&1 | tail -5

running 1 test
test parse::rdp::tests::test_bc_1_04_004_rejects_tpkt_length_mismatch ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 128 filtered out; finished in 0.00s
```

## EC-003 — Non-3389 Port Ignored

```
$ cargo test --lib test_bc_1_04_004_ignores_rdp_on_wrong_port 2>&1 | tail -5

running 1 test
test parse::rdp::tests::test_bc_1_04_004_ignores_rdp_on_wrong_port ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 128 filtered out; finished in 0.00s
```
