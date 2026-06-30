---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-06-30T00:00:00Z
phase: 2
inputs: [stories/S-10.01-capture-window-sanity-warning.md, behavioral-contracts/BC-INDEX.md]
traces_to: "P1-9"
id: "HS-011"
category: "edge-case-combinations"
must_pass: "true"
priority: "must-pass"
wave: 3
epic_id: "E-10"
behavioral_contracts: ["BC-4.01.004", "BC-4.01.005"]
lifecycle_status: active
introduced: v0.6.0-feature
---

# HS-011: Capture-window sanity warning fires on degenerate timestamps, silent on sane ones

> **NOT FOR IMPLEMENTERS.**

Black-box evaluator: judge only from the CLI and its outputs. Build your own
fixtures; do not read `src/`.

## Scenario

`otsniff analyze` warns — in the report header and on stderr — when the input
capture has a degenerate time base, and produces byte-for-byte the same output
as before when the time base is sane.

### Setup (build your own fixtures, stdlib only)

Construct minimal legacy PCAPs (24-byte global header + 16-byte record headers)
with controlled timestamps. You can adapt
`docs/demo-evidence/S-9.01/fixtures/make_pcaps.py` (which writes the record
`ts_sec` field). Make four captures, each ≥2 Ethernet/IPv4 packets:

- `epoch.pcap` — all record `ts_sec = 0` (all-epoch / 1970)
- `subsec.pcap` — packets within the same second (e.g. ts_sec all 1_700_000_000, differing only in `ts_usec`, total span < 1s)
- `nonmono.pcap` — second packet's `ts_sec` earlier than the first's
- `sane.pcap` — packets several seconds apart, in increasing order, year ~2024

### Checks

1. **Epoch warning (BC-4.01.004/005).** `analyze epoch.pcap -o e.html --md e.md`
   → exit 0, and BOTH (a) stderr contains a `WARNING:` line about
   no/epoch/1970 timestamps, and (b) `e.html` and `e.md` contain a capture
   timestamp warning banner. The existing "Capture window" line still renders.

2. **Sub-second warning.** `analyze subsec.pcap` → stderr `WARNING:` about a
   sub-second / <1s capture window; banner present in the report.

3. **Non-monotonic warning.** `analyze nonmono.pcap` → stderr `WARNING:` about
   non-monotonic / out-of-order timestamps; banner present.

4. **Sane capture is silent + unchanged.** `analyze sane.pcap -o s.html --md s.md`
   → exit 0, NO capture-sanity `WARNING:` on stderr, and NO timestamp-warning
   banner in `s.html` / `s.md`. (If you can produce a pre-S-10.01 baseline,
   the sane report should be byte-identical; otherwise assert the banner's
   absence and a normal report structure.)

5. **No panic / clean exit on all four.** Every invocation exits 0 and writes a
   readable HTML report.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-4.01.004 | epoch-zero / sub-second / non-monotonic detection from the time base |
| BC-4.01.005 | banner (HTML+MD) + stderr WARNING when degenerate; nothing emitted when sane |

## Verification Approach

- Run each of the four captures; capture stdout/stderr separately and grep the
  report files for the banner text.
- Assert presence on epoch/subsec/nonmono (checks 1–3), absence on sane (check 4).

## Evaluation Rubric

- Functional correctness (0.6): correct warning fires for each degenerate class.
- Edge case handling (0.3): sane capture is silent (no banner, no stderr line);
  no false positive.
- Performance (0.1): each run completes well under a second for tiny fixtures.

## Failure Guidance

"HOLDOUT LOW: HS-011 (satisfaction: 0.XX) — capture-sanity warning failed to
fire on a degenerate time base, or fired (banner/stderr) on a sane capture."
