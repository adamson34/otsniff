# AC-002: Default browser marker suppressed

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running tests/snapshot.rs (target/debug/deps/snapshot-2ad6c088c6f4c115)

running 1 test
test test_bc_8_01_005_summary_marker_suppressed ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s
```

## CSS excerpt (from `tests/snapshots/snapshot__report_html.snap`)

```css
  details.finding > summary::-webkit-details-marker { display: none; }
  details.finding > summary {
    cursor: pointer;
```

Note: chevron uses `var(--muted)` (existing token from S-5.06 `:root`); no new color tokens introduced.
