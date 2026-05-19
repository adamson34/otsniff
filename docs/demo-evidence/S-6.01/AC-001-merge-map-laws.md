# AC-001 — merge_map contract (BC-5.03.001)

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.12s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 8 tests
test scrub::tests::test_bc_5_03_001_load_rejects_map_with_empty_pseudonym ... ok
test scrub::tests::test_bc_5_03_001_merge_preserves_baseline_pseudonyms ... ok
test scrub::tests::test_bc_5_03_001_merge_empty_baseline_is_identity_to_current ... ok
test scrub::tests::test_bc_5_03_001_new_identifiers_get_fresh_pseudonyms_from_max_plus_one ... ok
test scrub::tests::test_bc_5_03_001_separate_counters_for_ips_macs_names ... ok
test scrub::tests::test_bc_5_03_001_chained_merges_respect_accumulated_baseline ... ok
test scrub::tests::test_bc_5_03_001_round_trip_after_merge_uses_baseline_pseudonyms ... ok
test scrub::tests::test_bc_5_03_001_leak_detector_passes_after_merge ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 145 filtered out; finished in 0.00s
```

Command: `cargo test --lib scrub::tests::test_bc_5_03_001 2>&1 | tail -20`

## Merge contract

`merge_map(baseline, &observations)` guarantees three properties: (1) every real
identifier already present in `baseline` reuses its existing pseudonym unchanged;
(2) real identifiers seen in `observations` but absent from `baseline` receive fresh
pseudonyms whose counter begins at `baseline.max_index + 1` for that family, so no
collisions are possible; (3) counters are tracked independently per family —
`host_NNN`, `mac_NNN`, and `name_NNN` each advance separately — meaning a network
with 50 hosts and 3 named devices never confuses their index spaces. The returned map
contains all entries from both inputs.
