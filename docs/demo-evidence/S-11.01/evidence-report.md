# S-11.01 Demo Evidence Report

Story: Diff capture-window normalization (P1-11)
Branch: `feature/S-11.01-diff-window-normalization`
Recorded: 2026-06-30

## Summary

One VHS recording demonstrates rate-normalized `otsniff diff` against synthetic
fixtures: a single flow (`192.168.10.10 → 192.168.10.20:502`) captured over
three different durations. All tape files and the fixture generator are free of
absolute paths (POL-12 compliant; `/tmp` output paths are not user paths).

---

## AC Coverage

### AC-002 — duration artifact suppressed

**Demo:** `AC-002-003-diff-normalization` (first half)

`base.pcap` carries the flow over a **3900s** window (4 packets); `curr_steady.pcap`
carries the same flow over an **1800s** window (2 packets) — half the raw bytes,
half the duration, so the **per-second rate is unchanged**. Diffing them:

```
WARNING: capture windows differ 2.2× (baseline 3900s vs current 1800s); flow-shift ratios are rate-normalized (bytes/sec)
$ jq '.flow_shifts | length' A.json
0
```

The flow is **not** reported as a shift (rate ratio ≈ 1.1, below the 2× default).
Under the old raw-byte behavior its byte ratio ≈ 2.0 would have flagged it — a
pure duration artifact. The window-mismatch WARNING also fires (2.2×).

### AC-002 / EC-005 — real rate shift preserved

**Demo:** `AC-002-003-diff-normalization` (second half)

`curr_realshift.pcap` carries the same flow over **1800s** with **4 packets** —
**identical raw bytes** to the baseline (48 → 48) but **double the per-second
rate**. Diffing `base.pcap` against it:

```
$ jq -c '.flow_shifts[0] | {baseline_bytes, current_bytes, ratio}' B.json
{"baseline_bytes":48,"current_bytes":48,"ratio":2.166666666666667}
```

The flow **is** flagged at ~2.17× — a genuine rate doubling that raw byte
comparison (48 == 48 → ratio 1.0) would have missed entirely. The diff report's
flow-shift table is now headed "rate change" with an explanatory rate-note so the
equal byte columns next to a 2.17× ratio are never misread.

### AC-003 — window-mismatch warning

Both diffs involve a 3900s-vs-1800s window pair (> 2×), so a `WARNING:` is
emitted on stderr and a window-mismatch banner is rendered in the diff report.

### AC-004 / AC-005 — surfacing & scope

The flow-shift heading reflects the ratio basis ("rate" vs "volume"); a
rate-note appears whenever ratios are rate-normalized (including the within-2×
band where no mismatch banner shows). Only diff output changed — analyze/scrub
reports are byte-identical.

---

## Fixtures

| File | Window | Packets | Role |
|------|--------|---------|------|
| `fixtures/base.pcap` | 3900s | 4 | baseline |
| `fixtures/curr_steady.pcap` | 1800s | 2 | same rate, half duration → duration artifact (NOT flagged) |
| `fixtures/curr_realshift.pcap` | 1800s | 4 | same bytes, double rate → real shift (flagged ~2.17×) |

Regenerate with: `python3 docs/demo-evidence/S-11.01/fixtures/make_pcaps.py`
