# AC-002 — Round-trip exactness after merge

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test scrub::tests::test_bc_5_03_001_round_trip_after_merge_uses_baseline_pseudonyms ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 152 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_5_03_001_round_trip_after_merge 2>&1 | tail -10`

## Round-trip invariant

`unscrub(scrub(text, merged_map), merged_map) == text` holds for any text that
contains real identifiers drawn from the baseline, from the current capture, or
from both simultaneously. The fixture in `test_bc_5_03_001_round_trip_after_merge_uses_baseline_pseudonyms`
exercises this by constructing a sentence that references an IP that was already in
the baseline (`host_001`) alongside a freshly appended one (`host_003`), scrubbing
it with the merged map, and asserting the unscrubbed result equals the original.
