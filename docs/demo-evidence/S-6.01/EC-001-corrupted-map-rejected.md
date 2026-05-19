# EC-001 — Corrupted map rejected at load time

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src/lib.rs (target/debug/deps/otsniff-57ecb0330ca805f6)

running 1 test
test scrub::tests::test_bc_5_03_001_load_rejects_map_with_empty_pseudonym ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 152 filtered out; finished in 0.00s
```

Command: `cargo test --lib test_bc_5_03_001_load_rejects_map_with_empty_pseudonym 2>&1 | tail -10`

## Validation contract

`ScrubMap::validate()` is called automatically by the CLI whenever `--baseline-map`
is provided. It rejects any entry where the pseudonym key is an empty string or
where the real value is an empty string, returning an `OtError` with a descriptive
message before the merge proceeds. This ensures corrupted or hand-edited map files
are caught before they can produce undefined merge behavior.
