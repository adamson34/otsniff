# AC-002: No Progress Output Without `-v`

## CLI smoke test

```
running 1 test
test test_bc_9_04_001_no_verbose_no_progress_lines ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 0.00s
```

## Live run without `-v`

Command: `cargo run --quiet -- analyze tests/fixtures/Modbus.pcap -o /tmp/s5.01-quiet.html`

```
wrote /tmp/s5.01-quiet.html (0 findings across 2 hosts)
```

No `[parse]` lines appear on stderr. The only output is the completion
line written to stdout. Note that for a small fixture (~102 packets, ~1.1 KB)
the periodic emission thresholds (100,000 packets / 10 MB) would not be
crossed regardless, but without `-v` even the final summary line from
`ProgressReporter::finish()` is suppressed — `ProgressReporter` is
constructed with `verbose = false` when the flag is absent, so all
emission paths are dead-code for that run.
