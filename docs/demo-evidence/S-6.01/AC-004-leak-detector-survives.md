# AC-004 — Leak detector passes after merge

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test scrub::tests::test_bc_5_03_001_leak_detector_passes_after_merge ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 152 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_5_03_001_leak_detector_passes_after_merge 2>&1 | tail -10`

## Privacy invariant

The merge path does not bypass the privacy invariant. After `merge_map`, text
scrubbed with the merged map passes both checks in `src/ai/leak_detector.rs`:
`ensure_clean` (regex scan for IPv4/IPv6/MAC patterns) and
`ensure_no_map_values` (membership check against every real value in the map,
which catches hostnames that have no clean regex shape). No real identifier
present in either the baseline or the current capture can survive the scrub
layer when using the merged map.
