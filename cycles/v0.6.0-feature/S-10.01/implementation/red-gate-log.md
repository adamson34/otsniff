# Red-Gate Log — S-10.01 (Capture-window sanity warning)

Branch: `feature/S-10.01-capture-sanity-warning`
TDD mode: strict. Tests written and observed FAILING (on assertions) before the
implementation that makes them pass.

Commit ordering (verified `git log develop..HEAD`):

| Order | Commit | Kind |
|---|---|---|
| 1 | `2fc6504` | **test**(capture-sanity): failing tests + stubs for S-10.01 (red gate) |
| 2 | `ffe498a` | feat(capture-sanity): capture-window sanity warning (S-10.01) |

## Red gate (at commit `2fc6504`, against stubs `assess → vec![]`, `message → ""`)

**`capture_sanity` unit tests:**
```
all_epoch_capture_is_epoch_zero          left: []  right: [EpochZeroTimestamps]
three_packets_spanning_sub_second...     left: []  right: [SubSecondWindow]
out_of_order_spanning_minutes...         left: []  right: [NonMonotonicTimestamps]
out_of_order_and_sub_second...           left: []  right: [SubSecondWindow, NonMonotonicTimestamps]
every_message_is_non_empty_and_stable    (message stub "" → assert !is_empty fails)
test result: FAILED. 5 passed; 5 failed
```

**Observer tracking tests** (min/max/monotonic not yet added):
```
observe_tracks_min_max_and_monotonic...  left: None  right: Some(2023-11-14T22:13:20Z)
observe_flags_non_monotonic...           assertion failed: !obs.timestamps_monotonic
test result: FAILED. 0 passed; 2 failed
```

**Snapshot banner test:** panicked — "HTML banner must carry the epoch-zero message" (FAILED).

**cli_smoke:** `s_10_01_analyze_epoch_zero_pcap_warns_on_stderr` FAILED (stderr had only `wrote ...`, no WARNING). `s_10_01_analyze_sane_pcap_emits_no_capture_warning` passed pre-change (byte-identity guard already held).

## Green (post-implementation, independently re-verified by orchestrator)

- `cargo fmt --all -- --check` → clean
- `cargo clippy --all-targets --workspace -- -D warnings` → clean (0 warnings)
- `cargo test --workspace` → 659 passed, 0 failed (lib 315, snapshot 87, cli_smoke + all others)
- Snapshots: only 2 NEW (`report_html_capture_warning`, `report_md_capture_warning`); ZERO pre-existing snapshots modified (AC-005 byte-identity holds).
- No `Cargo.toml` change; no `.factory/` change from the code branch.
- Live behavioral check (4 fixtures): epoch→EpochZero, subsec→SubSecond, nonmono→NonMonotonic (each: stderr WARNING + report banner); sane→silent (no warning, no banner).
