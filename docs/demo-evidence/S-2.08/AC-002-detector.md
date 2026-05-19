# AC-002 — Detector (BC-3.04.006)

## Integration Tests

```
$ cargo test --test rdp_legacy 2>&1 | tail -15

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/rdp_legacy.rs (target/debug/deps/rdp_legacy-3b1d5c67d19b497b)

running 5 tests
test test_bc_3_04_006_negative_protocol_hybrid_ex_does_not_fire ... ok
test test_bc_3_04_006_negative_protocol_hybrid_does_not_fire ... ok
test test_bc_3_04_006_negative_protocol_ssl_does_not_fire ... ok
test test_bc_3_04_006_positive_protocol_rdp_fires_critical ... ok
test test_bc_3_04_006_rolls_up_by_src_dst ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Rule Catalog Entry

```
$ cargo run --quiet -- rules 2>&1 | grep -A3 "rdp_no_nla"

| [`creds.rdp_no_nla`](#credsrdp_no_nla) | critical | RDP connection without Network Level Authentication (NLA) |
| [`egress.ot_to_internet`](#egressot_to_internet) | critical | Internet-bound traffic from OT subnets |
| [`boundary.dns_resolver`](#boundarydns_resolver) | medium | DNS queries from OT to an out-of-zone resolver |
| [`boundary.ntp_external`](#boundaryntp_external) | medium | OT host syncing time to public NTP |
--
## `creds.rdp_no_nla`

**RDP connection without Network Level Authentication (NLA)**
```

## Snapshot Wiring Test

```
$ cargo test --test snapshot creds_rdp_no_nla_wired_into_run_all 2>&1 | tail -5

running 1 test
test creds_rdp_no_nla_wired_into_run_all ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 52 filtered out; finished in 0.00s
```
