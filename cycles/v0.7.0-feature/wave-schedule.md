---
document_type: wave-schedule
project: otsniff
cycle: v0.7.0-feature
level: ops
version: "1.0"
status: active
producer: wave-scheduling (S-13.01 decomposition)
timestamp: 2026-09-07T00:00:00Z
updated: 2026-09-07T00:00:00Z
---

# Wave Schedule — otsniff v0.7.0-feature cycle

v0.6.0-feature closed with all 5 waves gated (see
`cycles/v0.6.0-feature/wave-schedule.md`); develop is bumped to
`0.7.0-dev.1`. This cycle opens with an infrastructure story (P1-14) that
does not itself ship user-facing behavior but unblocks the planned
otsniff-hunt companion tool.

## Waves

| Wave | Story | Traces to | Points | BCs | Status |
|---|---|---|---|---|---|
| 1 | S-13.01 — Extract privacy/scrub layer into `crates/otsniff-privacy` | P1-14 | 8 | BC-5.01.001..004, BC-5.02.001..003, BC-5.03.001 | ready — awaiting phase-3 delivery |

## Wave 1 — S-13.01

**Scope.** Move the pure, formally-verified mechanics of the privacy layer
(`ScrubMap`, `scrub_text`/`unscrub_text`, pseudonym-counter internals, and the
fail-closed `leak_detector`) out of `src/scrub.rs` / `src/ai/leak_detector.rs`
into a new workspace crate `crates/otsniff-privacy`, following the exact
crate-extraction precedent ADR-0013 set for `crates/zonewarden`. Otsniff-specific
population logic (`build_map`/`merge_map`, which walks `Observations`/`HostObs`)
stays in `src/`. Pure refactor — no observable behavior change; all ~40 existing
tests and both Kani proof modules move with the code they cover.

**Touches.** New `crates/otsniff-privacy/`; `src/scrub.rs` (trimmed to
population only); `src/ai/leak_detector.rs` (removed); `src/error.rs`
(`OtError::PrivacyLeak{..}` → `OtError::Privacy(#[from] otsniff_privacy::PrivacyError)`,
mirroring `Segmentation`); call sites in `ai/mod.rs`, `cli.rs`, `audit.rs`,
`findings/augmented.rs`, `kani_proofs.rs`; `kani.yml` + mutation-testing config
path updates. See `docs/adr/0016-otsniff-privacy-crate.md` and
`stories/S-13.01-otsniff-privacy-crate-extraction.md` for full detail.

**Why this branch is already open.** `feat/otsniff-privacy-crate` was created
off `develop` ahead of this cycle being formally opened, in the same working
session that produced ADR-0016; it is currently empty (0 commits) and ready
for phase-3 delivery against this story.

**Independence.** No file overlap with the parallel, already-spec'd
`feat/trusted-writer-impl` branch (P1-12, ADR-0015) — that branch touches
findings/CLI filtering, not the privacy/scrub layer.

## Previous cycle

v0.6.0-feature — 5 waves, 5 stories (S-8.01..S-12.01), all gated. Full wave
schedule: `cycles/v0.6.0-feature/wave-schedule.md`.
