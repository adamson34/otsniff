# AC-002 — No display regression in existing snapshot tests

**Story:** S-2.02  
**Criterion:** After introducing dedup, all existing `tests/snapshot.rs` tests produce no diff.

---

## Snapshot test run

Command (relevant tail):

```
cargo test --test snapshot 2>&1 | tail -15
```

Output:

```
test unscrub_round_trip_recovers_real_values ... ok
test dnp3_engineering_fires_on_operate_calls ... ok
test default_task_snapshot ... ok
test recon_port_scan_fires_at_threshold ... ok
test system_prompt_snapshot ... ok
test recon_port_scan_escalates_at_high_threshold ... ok
test scrub_map_snapshot ... ok
test findings_json_snapshot ... ok
test scrubbed_markdown_snapshot_does_not_leak_real_values ... ok
test html_report_snapshot ... ok
test system_prompt_for_each_source_tag_snapshots ... ok
test invariant_no_real_values_reach_ai_provider ... ok

test result: ok. 50 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

**Result: 50 passed, 0 failed.**

---

## Why snapshots are unaffected

The snapshot fixtures in `tests/snapshot.rs` construct `CredEvent` values directly with
`count: 1` (a unit value, which is also what the pre-dedup path produced for single-packet
observations). The rendering layer in `src/findings/plaintext_creds.rs` was updated to read
the `count` field, but for `count == 1` the display output is identical to the previous
format. Snapshots therefore require no `cargo insta review` acceptance step for this story.
