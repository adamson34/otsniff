# Verbose Mode Live Run

## Command

```
cargo run --quiet -- analyze tests/fixtures/Modbus.pcap -v -o /tmp/s5.01-verbose.html
```

## Output (stderr + stdout combined)

```
otsniff 0.4.0-dev.1 — analyzing tests/fixtures/Modbus.pcap
  parsed 102 packets, 2 hosts, 2 flows
[parse] processed 102 packets / 1.1 KB
wrote /tmp/s5.01-verbose.html (0 findings across 2 hosts)
```

The `[parse] processed 102 packets / 1.1 KB` line is the final summary
emitted by `ProgressReporter::finish()` in verbose mode. For this small
fixture (102 packets, ~1.1 KB) the periodic emission thresholds (100,000
packets / 10 MB) are never reached, so only the `finish()` summary
appears. For large captures the periodic line would also appear; that
path is covered by unit tests via MockClock injection in
`progress::tests::test_bc_9_04_001_emits_after_100k_packets` and
`test_bc_9_04_001_emits_after_10mb_bytes`.
