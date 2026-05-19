# Performance Baseline

Timings captured on 2026-05-19 (macOS arm64, Apple M-series, release profile).
All criterion measurements are median over 100 samples.

## Microbenchmarks (criterion) — Baseline

| Benchmark | Median | Notes |
|-----------|--------|-------|
| `parse_modbus` | 1.28 ns/iter | Single MBAP-framed Write Single Coil frame (12 bytes) |
| `parse_enip_header` | 0.63 ns/iter | EtherNet/IP encapsulation header parse (24-byte read) |
| `parse_enip_cip` | 1.36 ns/iter | CIP engineering-class heuristic scan on SendRRData frame |
| `parse_s7comm` | 1.25 ns/iter | TPKT+COTP+S7 Job frame with Write Var (19 bytes) |
| `parse_dhcp` | 38.3 ns/iter | DHCP ACK option-walk (option 12 hostname + yiaddr) |
| `observe_pipeline_100` | 47.7 µs/iter | Full observer pipeline: 100 Modbus packets to `finish()` |
| `findings_run` | 4.96 µs/iter | `run_all_findings` against a synthetic `Observations` fixture |

## End-to-end (hyperfine)

Target: `otsniff analyze tests/fixtures/synthetic-1mb.pcap -o /tmp/out.html`

Run `hyperfine --warmup 2 --runs 10 "target/release/otsniff analyze tests/fixtures/synthetic-1mb.pcap -o /tmp/out.html"` to regenerate.
The perf.yml CI workflow captures this automatically on each scheduled run.

| Command | Mean (s) | Min (s) | Max (s) | Runs |
|---------|----------|---------|---------|------|
| `otsniff analyze synthetic-1mb.pcap` | — | — | — | — |

*Note: end-to-end timing is captured by the perf.yml CI workflow. Values appear after the first scheduled CI run. The synthetic-1mb.pcap fixture (~12k packets, 1 MiB) is representative of a small to mid-size plant capture.*

## Regression Threshold

Alert (soft, non-blocking) fires when criterion reports a measured median
more than **2x** the baseline for any individual bench. The threshold is
configurable per benchmark — see AC-003 in
`S-3.01-criterion-benchmarks.md`.

The perf.yml CI workflow emits a `::warning::` annotation (visible in
GitHub Actions) but does **not** fail the build when a regression is
detected. This avoids noisy CI failures from cloud runner variance while
still surfacing slowdowns for human review.

To record a new baseline after an intentional optimization:

```bash
cargo bench -- --save-baseline initial
```
