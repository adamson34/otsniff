# AC-002: Detector — `ics.modbus_unit_id_sweep` (BC-3.03.006)

## Detector Tests

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/modbus_recon.rs (<REPO_ROOT>/target/debug/deps/modbus_recon-3d8e9db53fc74fdd)

running 7 tests
test test_bc_3_03_006_at_medium_threshold_fires_medium ... ok
test test_bc_3_03_006_at_high_threshold_fires_high ... ok
test test_bc_3_03_006_below_threshold_does_not_fire ... ok
test test_bc_3_03_006_evidence_includes_count_and_first_10_ids ... ok
test test_bc_3_03_006_distinct_src_dst_pairs_emit_separate_findings ... ok
test test_bc_3_03_006_well_above_medium_fires_medium ... ok
test test_bc_3_03_006_well_above_high_fires_high ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Rule Catalog

```
| [`ics.modbus_unit_id_sweep`](#icsmodbus_unit_id_sweep) | medium | Modbus unit-ID sweep — PLC discovery or fuzzing pattern |
| [`egress.ot_to_internet`](#egressot_to_internet) | critical | Internet-bound traffic from OT subnets |
| [`boundary.dns_resolver`](#boundarydns_resolver) | medium | DNS queries from OT to an out-of-zone resolver |
| [`boundary.ntp_external`](#boundaryntp_external) | medium | OT host syncing time to public NTP |
--
## `ics.modbus_unit_id_sweep`

**Modbus unit-ID sweep — PLC discovery or fuzzing pattern**
```

## Wiring Test

```
running 1 test
test ics_modbus_unit_id_sweep_wired_into_run_all ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 53 filtered out; finished in 0.00s
```

## Notes

Severity ladder: the detector fires at **Medium** when `unit_ids.len() >= 5` for any
`(src, dst)` pair, and escalates to **High** at `>= 50` distinct unit IDs. Evidence in
the finding lists the `(src, dst)` pair plus the unit-id count and the first 10 IDs
(sorted ascending). This two-tier ladder distinguishes opportunistic scanning
(5–49 IDs, Medium) from systematic PLC enumeration or fuzzing (50+ IDs, High).
