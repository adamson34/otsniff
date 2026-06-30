# S-10.01 Demo Evidence Report

Story: Capture-window sanity warning (P1-9)
Branch: `feature/S-10.01-capture-sanity-warning`
Recorded: 2026-06-30

## Summary

One VHS recording demonstrates the degenerate→warning / sane→silent contrast
against stdlib-Python synthetic fixtures (four captures differing only in their
record timestamps). All tape files and the fixture generator are free of
absolute paths (POL-12 compliant; `/tmp` output paths are not user paths).

---

## AC Coverage

### AC-002 / AC-003 / AC-004 (BC-4.01.004/005) — degenerate timestamps warn

**Demo:** `AC-002-005-capture-sanity` (first half)

`otsniff analyze epoch.pcap` (all record timestamps at the Unix epoch) emits a
**stderr WARNING** and a **report banner**:

```
WARNING: capture has no real timestamps (all at/before the Unix epoch); time-based findings are unreliable
```

`grep -i 'timestamp warning' epoch.md` shows the banner line in the report.
The other two degenerate classes behave identically (verified outside the
recording):

| Fixture | Timestamps | Warning |
|---|---|---|
| `epoch.pcap` | all at epoch 0 | `EpochZeroTimestamps` — "no real timestamps …" |
| `subsec.pcap` | within one second | `SubSecondWindow` — "spans less than one second …" |
| `nonmono.pcap` | 2nd packet earlier than 1st | `NonMonotonicTimestamps` — "not monotonically increasing …" |

### AC-005 — sane captures are silent + byte-identical

**Demo:** `AC-002-005-capture-sanity` (second half)

`otsniff analyze sane.pcap` (timestamps seconds apart, ascending) emits **no**
capture-sanity WARNING and **no** banner — `grep -c 'timestamp warning'` returns
`0`. The clean-capture HTML/MD/JSON output is byte-identical to pre-S-10.01
(locked by every pre-existing report/MD/JSON snapshot staying green unmodified;
only two brand-new degenerate-fixture snapshots were added).

---

## Fixtures

| File | Timestamps | Exercises |
|------|-----------|-----------|
| `fixtures/epoch.pcap` | all `ts_sec = 0` | `EpochZeroTimestamps` |
| `fixtures/subsec.pcap` | same second, < 1s span | `SubSecondWindow` |
| `fixtures/nonmono.pcap` | second packet earlier | `NonMonotonicTimestamps` |
| `fixtures/sane.pcap` | seconds apart, ascending | no warning (silent) |

Regenerate with: `python3 docs/demo-evidence/S-10.01/fixtures/make_pcaps.py`
