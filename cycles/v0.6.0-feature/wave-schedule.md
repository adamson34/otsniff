---
document_type: wave-schedule
project: otsniff
cycle: v0.6.0-feature
level: ops
version: "1.0"
status: active
producer: wave-scheduling (S-9.01 decomposition)
timestamp: 2026-06-30T00:00:00Z
updated: 2026-06-30T00:00:00Z
---

# Wave Schedule — otsniff v0.6.0-feature cycle

The v0.6.0-feature cycle delivers the P0 roadmap items remaining after
v0.5.0, one story per wave. Stories are independent (no shared files at
the contract level), so each wave is a single story delivered through the
full per-story pipeline with its own wave gate.

## Waves

| Wave | Story | Traces to | Points | BCs | Status |
|---|---|---|---|---|---|
| 1 | S-8.01 — mDNS / NetBIOS-NS / LLMNR hostname extraction | P0-9 | 5 | BC-1.02.010..013 | ✅ gated (PR #138, merge 6334e36) |
| 2 | S-9.01 — Multi-PCAP / rotated-capture analyze | P0-10 | 5 | BC-1.01.003, BC-1.01.004, BC-7.01.005 | in-progress (phase-3 delivery) |

## Wave 2 — S-9.01

**Scope.** `otsniff analyze a.pcap b.pcap c.pcap -o report.html` ingests the
named captures in command-line order and treats them as one logical capture
(append/CLI-order semantics — no timestamp sort), emitting a single report over
the union window.

**Touches.** `src/pcap.rs` (`iter_packets_multi`, `peek_link_type`,
`MultiPacketIter`), `src/cli.rs` (`AnalyzeArgs.inputs: Vec<PathBuf>`,
`analyze(&[PathBuf])`, multi-file source label), `src/audit.rs`
(`input_pcaps: Vec<InputDescriptor>`, `SCHEMA_VERSION` 1→2), `src/error.rs`
(`OtError::MixedLinkTypes`).

**Independence from Wave 1.** S-8.01 touched `src/parse/*` + `src/observe.rs`;
S-9.01 touches the ingestion/CLI/audit shell. No file overlap at the
contract level — Wave 2 builds cleanly on the gated Wave 1 tree.

**Out of scope.** `scrub` (single-file) and `diff` (two-file) keep their
positional signatures; no timestamp-based global sort; no cross-file packet
dedup. See `stories/S-9.01-multi-pcap-analyze.md` for the full edge-case table.

## Previous cycle

v0.4.0-feature — 3 waves, 38 stories, 125 points. All 6 wave gates passed.
Full wave schedule: `cycles/v0.4.0-feature/wave-schedule.md`.

## v0.5.0 backfill

Two items delivered outside the VSDD pipeline prior to this cycle (recorded for
traceability only, not counted toward v0.6.0 wave totals):

- S-7.01 Zonewarden segmentation-conformance (ADR-0013, PRs #123–#130)
- S-7.02 Segmentation drift — `diff --policy` (P1-13, PR #136)
