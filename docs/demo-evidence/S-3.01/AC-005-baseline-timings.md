# AC-005: Baseline timings

## Baseline table from `docs/PERF.md`

```
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
```

Baseline covers all 6 criterion benches plus a hyperfine end-to-end section.
