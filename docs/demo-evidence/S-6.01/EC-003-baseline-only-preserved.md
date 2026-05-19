# EC-003 — Baseline-only entries preserved after merge

## Test excerpt (from `src/scrub.rs` HEAD)

```rust
fn test_bc_5_03_001_merge_preserves_baseline_pseudonyms() {
    let baseline = scrub_map_from(
        &[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")],
        &[],
        &[],
    );
    // current has 10.0.0.1 (already in baseline) and 10.0.0.99 (new).
    // 10.0.0.2 is NOT in current — EC-003 scenario.
    let obs = obs_with_ips(&["10.0.0.1", "10.0.0.99"]);

    let merged = merge_map(baseline, &obs);

    // Baseline pseudonym for 10.0.0.1 must be preserved.
    assert_eq!(
        merged.ips.get("host_001").map(String::as_str),
        Some("10.0.0.1"),
        "baseline pseudonym host_001 must be preserved"
    );

    // host_002 -> 10.0.0.2 must be preserved (EC-003: not in current).
    assert_eq!(
        merged.ips.get("host_002").map(String::as_str),
        Some("10.0.0.2"),
        "baseline entry not in current must be preserved (EC-003)"
    );
```

Source: `git show HEAD:src/scrub.rs | grep -A25 "test_bc_5_03_001_merge_preserves_baseline_pseudonyms" | head -30`

## Note

The host `10.0.0.2` appears only in the baseline, not in the current capture's
observations. After `merge_map`, the entry `host_002 -> 10.0.0.2` is present in
the merged map. Baseline-only entries are preserved unconditionally; a future
story may decide whether to prune stale entries, but the default is retain.
