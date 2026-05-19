# AC-003 — CLI `--baseline-map` flag

## Help text fragment

```
      --baseline-map <PATH>
          Optional path to a previously saved pseudonym map to use as a baseline. When provided, real identifiers already in the baseline map reuse their existing pseudonyms; new identifiers are appended with fresh pseudonyms. If omitted, the current behavior is preserved (a brand-new map is built from this capture alone).
```

Command: `cargo run --quiet -- scrub --help 2>&1 | grep -A1 baseline-map`

## CLI integration test

```
running 1 test
test test_bc_5_03_001_baseline_map_flag_extends_pseudonyms ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out; finished in 0.00s
```

Command: `cargo test --test cli_smoke test_bc_5_03_001_baseline_map_flag_extends_pseudonyms 2>&1 | tail -5`

## Note

The CLI integration test (`test_bc_5_03_001_baseline_map_flag_extends_pseudonyms`)
passes in this environment — it uses a synthetic minimal PCAP fixture embedded in
the test rather than depending on `tests/fixtures/Modbus.pcap`. The unit tests above
(AC-001/AC-002/AC-004) cover the merge contract in full. A live two-capture
demonstration showing pseudonym stability across real captures is deferred to
S-6.02, which adds the `diff` subcommand that exercises this end-to-end.
