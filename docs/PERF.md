# Performance Baseline

<!-- TODO (S-3.01 implementer): Fill in baseline numbers after the first real
criterion run and hyperfine end-to-end measurement. Steps:
  1. Build release binary: cargo build --release
  2. Run microbenchmarks: cargo bench
  3. Run end-to-end: hyperfine --warmup 2 --runs 10 \
       "target/release/otsniff analyze tests/fixtures/synthetic-1mb.pcap \
        -o /tmp/out.html"
  4. Paste the generated criterion comparison table and hyperfine summary below.
-->

## Microbenchmarks (criterion)

<!-- TODO: paste criterion HTML summary or copy the bench output table here. -->

| Benchmark | Median | Mean | Std dev | Notes |
|-----------|--------|------|---------|-------|
| `parse_modbus` | — | — | — | Stub; no baseline yet |
| `parse_enip` | — | — | — | Stub; no baseline yet |
| `parse_s7comm` | — | — | — | Stub; no baseline yet |
| `parse_dhcp` | — | — | — | Stub; no baseline yet |
| `observe_pipeline` | — | — | — | Stub; no baseline yet |
| `findings_run` | — | — | — | Stub; no baseline yet |

## End-to-end (hyperfine)

<!-- TODO: paste hyperfine output table here after running against
tests/fixtures/synthetic-1mb.pcap. -->

| Command | Mean (s) | Min (s) | Max (s) | Runs |
|---------|----------|---------|---------|------|
| `otsniff analyze synthetic-1mb.pcap` | — | — | — | — |

## Regression Threshold

Alert (soft, non-blocking) fires when criterion reports a measured median
more than 2x the baseline for any individual bench. Threshold is
configurable per benchmark via the criterion `SamplingMode` / baseline
compare configuration. See AC-003 in `S-3.01-criterion-benchmarks.md`.
