# AC-001: Criterion benchmark files

## Acceptance check output

```
PASS: AC-001a: all 6 bench files exist (parse_modbus, parse_enip, parse_s7comm, parse_dhcp, observe_pipeline, findings_run)
PASS: AC-001b: cargo bench --no-run exits 0 — all bench files compile
PASS: AC-001c: Cargo.toml has all 6 bench names and each [[bench]] sets harness = false
PASS: AC-001d: all 6 bench files have real workloads (no black_box(0u8) stub marker)
```

All 4 AC-001 sub-checks pass.

## Summary

6 benchmark files exist under `benches/` with real workloads:

- `benches/parse_modbus.rs`
- `benches/parse_enip.rs`
- `benches/parse_s7comm.rs`
- `benches/parse_dhcp.rs`
- `benches/observe_pipeline.rs`
- `benches/findings_run.rs`

None contain `black_box(0u8)` stub markers — all benches exercise actual parsing and
pipeline logic against deterministic byte fixtures.
