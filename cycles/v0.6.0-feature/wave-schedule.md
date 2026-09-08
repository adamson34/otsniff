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
| 2 | S-9.01 — Multi-PCAP / rotated-capture analyze | P0-10 | 5 | BC-1.01.003, BC-1.01.004, BC-7.01.005 | ✅ gated (PR #140, merge 030a279) |
| 3 | S-10.01 — Capture-window sanity warning | P1-9 | 5 | BC-4.01.004, BC-4.01.005 | ✅ gated (PR #143, merge 668d704) |
| 4 | S-11.01 — Diff capture-window normalization | P1-11 | 5 | BC-3.08.004, BC-3.08.005 | ✅ gated (PR #145, merge ad37626) |
| 5 | S-12.01 — MITRE ATT&CK for ICS technique mapping | P1-6 | 8 | BC-3.06.006, BC-8.05.001 | ✅ gated (PR #147, merge 5525b5c) |

## Wave 5 — S-12.01

**Scope.** Map every detector rule to MITRE ATT&CK for ICS techniques and surface
them per finding in the report. The catalog already tags 8/15 rules; this maps
the remaining 7 (creds→T0859, smbv1→T0866, stale/weak TLS→T0830, dns/ntp→T0884,
some "supporting") and renders per-finding techniques as links to attack.mitre.org
in HTML, markdown, and JSON — via the existing `metadata_for(id)` catalog lookup
(the `trigger` enrichment pattern). MITRE data stays in the catalog
(single source of truth, **ADR-0014**), not duplicated onto `Finding`.

**Touches.** `src/findings/{7 modules}.rs` (data), `src/report.rs` +
`templates/report.html` + `src/report_md.rs` (rendering), `src/cli.rs` (JSON),
`docs/RULES.md` (regen), `docs/adr/0014-*.md`. M-sized (8 pts). No dep.

## Wave 4 — S-11.01

**Scope.** Rate-normalize `otsniff diff` flow-shift detection by each side's
capture-window duration (from S-10.01's `min_ts`/`max_ts`) so steady-state flows
over unequal-duration captures aren't reported as duration-artifact "shifts";
fall back to raw byte ratio when a window is degenerate (<1s); warn (stderr +
diff-report banner) on a >2× window mismatch or a degenerate window.

**Touches.** `src/diff.rs::compute_with_multiplier` (rate normalization + new
`Diff` fields), `src/cli.rs::run_diff` (stderr WARNING), `templates/diff.html` +
`src/report_md.rs` (conditional banner). **Depends on S-10.01** (the
`min_ts`/`max_ts` duration source). Intentionally changes diff snapshots (ratio
is now rate-based); analyze/scrub output is unaffected.

## Wave 3 — S-10.01

**Scope.** Flag degenerate capture timestamps (all-epoch/1970, sub-second
window, non-monotonic ordering) in the report header (HTML + MD banner) and on
stderr, so time-dependent results aren't silently trusted. Pure detector
`capture_sanity::assess` over observer-tracked `min_ts`/`max_ts`/monotonic;
rendered **only when degenerate** → sane captures byte-identical (no churn).
Also explains the TD-S901-002 out-of-order multi-file window inversion.

**Touches.** `src/capture_sanity.rs` (new), `src/observe.rs` (ts tracking),
`src/report.rs` + `templates/report.html` + `src/report_md.rs` (banner),
`src/cli.rs` (stderr WARNING). Independent of waves 1–2 (capture-quality surface).

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
