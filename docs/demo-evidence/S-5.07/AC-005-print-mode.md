# AC-005: Print mode forces expanded state

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/snapshot.rs (target/debug/deps/snapshot-2ad6c088c6f4c115)

running 1 test
test test_bc_8_01_005_print_mode_forces_open ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s
```

## CSS excerpt (from `tests/snapshots/snapshot__report_html.snap`)

```css
    .finding { break-inside: avoid; }
    details.finding > *:not(summary) { display: block !important; }
    details.finding > summary::-webkit-details-marker,
    details.finding > summary::before { display: none !important; content: "" !important; }
```

`details.finding > *:not(summary) { display: block !important; }` forces all finding card content to render fully when printing, regardless of user collapse state.
