# AC-004: Nested `<details>` for evidence/criteria/playbook preserved

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/snapshot.rs (target/debug/deps/snapshot-2ad6c088c6f4c115)

running 1 test
test test_bc_8_01_005_nested_evidence_still_present ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s
```

## Rendered HTML excerpt showing nested structure (from `tests/snapshots/snapshot__report_html.snap`)

```html
  <details open class="finding sev-critical">
    <summary><span class="badge sev-critical">critical</span>Telnet session observed (cleartext by definition)</summary>
    <div>1 Telnet packet(s) seen across 1 host(s). Credentials traversing these flows should be considered exposed.</div>

    <details>
      <summary>Evidence (1 sample)</summary>
      <pre class="evidence">PLC-LINE3 (10.10.0.20):23 (1 packet(s))
```

Note: Investigation playbook remains `<details open>` per S-5.05 pattern; CSS chevron scoping prevents inner and outer chevrons from conflicting.
