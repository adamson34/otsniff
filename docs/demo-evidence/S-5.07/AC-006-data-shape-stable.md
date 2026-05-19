# AC-006: Data-shape stability guard

## Test output

```
running 1 test
test render_html_snapshot_remains_data_stable ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s
```

Snapshot diff was purely structural (`<div class="finding sev-...">` replaced by `<details open class="finding sev-...">` + `<summary>` wrapper); zero changes to finding IDs, IPs, byte counts, packet counts, or timestamps.
