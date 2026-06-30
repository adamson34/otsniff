# Red-Gate Log — S-11.01 (Diff capture-window normalization)

Branch: `feature/S-11.01-diff-window-normalization`
TDD mode: strict. Tests written and observed FAILING (on assertions) before the
implementation that makes them pass.

Commit ordering (verified `git log develop..HEAD`):

| Order | Commit | Kind |
|---|---|---|
| 1 | `cb7603a` | **test**(diff): red gate for capture-window normalization (S-11.01) |
| 2 | `bd45f33` | feat(diff): rate-normalize flow-shift ratios by capture window (S-11.01) |

## Red gate (at commit `cb7603a`)

**Diff unit test — worked example** (loop still on raw byte ratios):
```
thread 'diff::tests::s_11_01_worked_example_steady_flow_not_flagged_when_rate_normalized'
panicked at src/diff.rs: rate ratio is 1.0 (2X/3600 vs X/1800) ⇒ steady flow must NOT be
flagged; got [FlowDelta { ... baseline_bytes: 2000, current_bytes: 1000, ratio: 2.0 }]
test result: FAILED. 2 passed; 1 failed
```

**CLI smoke — window-mismatch WARNING:**
```
thread 's_11_01_diff_mismatched_windows_warns_on_stderr'
panicked at tests/cli_smoke.rs: failed var.contains("capture windows differ")
├── var: wrote .../diff.md (0 new hosts, 0 gone, 0 new findings, 0 resolved)
test result: FAILED. 1 passed; 1 failed
```

(The other three new tests — real-rate-doubled-still-flagged, degenerate
fallback, comparable-windows-no-warning — hold under the raw-ratio stub too, so
they passed at red; the two above are the assertion-level red gates.)

## Green (post-implementation, independently re-verified by orchestrator)

- `cargo fmt --all -- --check` → clean
- `cargo clippy --all-targets --workspace -- -D warnings` → clean (0 warnings)
- `cargo test --workspace` → 664 passed, 0 failed
- Snapshots: only the 2 diff snapshots changed (`diff_html_report`,
  `diff_markdown_report` — the banner CSS + capture-windows line); NO analyze/scrub
  snapshot changed (AC-005). No `Cargo.toml` / `.factory/` change.

## Live behavioral verification (orchestrator, against synthetic fixtures)

One flow 192.168.10.10→.20:502 across three captures:

| Diff | Windows | Raw byte ratio | Result |
|---|---|---|---|
| base (4 pkts/3900s) vs curr_steady (2 pkts/1800s) | 3900 vs 1800 | 2.0 (would flag) | **0 flow-shifts** — duration artifact suppressed; window WARNING (2.2×) |
| base (4 pkts/3900s) vs curr_realshift (4 pkts/1800s) | 3900 vs 1800 | 1.0 (bytes 48=48) | **1 flow-shift** ratio 2.17× — real rate doubling preserved |

The realshift case is the clean proof: identical raw bytes (48→48) yet correctly
flagged because the per-second rate doubled (window halved).
