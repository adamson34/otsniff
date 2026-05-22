# AC-002 — Bit-Test Spec Discrepancy and Implementation Correction

## Spec vs Implementation

AC-002 as written specifies the firing condition as:

    selected_protocol & 0x01 == 0

That bitmask tests only bit 0 (PROTOCOL_SSL = 0x01). It would **spuriously fire**
on PROTOCOL_HYBRID (0x02) and PROTOCOL_HYBRID_EX (0x08), both of which indicate a
secure negotiation — NLA or CredSSP are in play for both. Firing on those would
produce false-positive Critical findings in environments with modern RDP.

The implementation uses **exact equality** instead:

    selected_protocol == 0x00000000   // PROTOCOL_RDP only

This fires only when the server selected bare PROTOCOL_RDP (no SSL, no NLA, no
CredSSP), which is the genuine no-NLA condition. The three negative tests confirm
that PROTOCOL_SSL (0x01), PROTOCOL_HYBRID (0x02), and PROTOCOL_HYBRID_EX (0x08)
do not trigger the finding:

```
$ cargo test --test rdp_legacy -- 2>&1 | tail -15

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/rdp_legacy.rs (target/debug/deps/rdp_legacy-3b1d5c67d19b497b)

running 5 tests
test test_bc_3_04_006_negative_protocol_hybrid_ex_does_not_fire ... ok
test test_bc_3_04_006_negative_protocol_ssl_does_not_fire ... ok
test test_bc_3_04_006_negative_protocol_hybrid_does_not_fire ... ok
test test_bc_3_04_006_positive_protocol_rdp_fires_critical ... ok
test test_bc_3_04_006_rolls_up_by_src_dst ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

BC-3.04.006 was registered with the corrected exact-equality condition, so the
behavioral contract is authoritative; the story AC wording is the stale artefact.
