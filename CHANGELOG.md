# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed

- **Internal refactor:** extracted the pseudonym scrub/unscrub mechanics and
  the fail-closed leak detector into a new workspace crate,
  `crates/otsniff-privacy` (ADR-0016). `ScrubMap`, `scrub_text`/
  `unscrub_text`, `pseudonym_regex`, and `leak_detector::{scan, ensure_clean,
  ensure_no_map_values}` moved out of `src/scrub.rs` and
  `src/ai/leak_detector.rs` verbatim, along with their Kani proofs and unit
  tests. `otsniff`'s own `src/scrub.rs` keeps only the population functions
  (`build_map`, `build_map_at`, `merge_map`) that walk otsniff's
  `Observations` capture model.
  - No user-facing or CLI behavior change: `otsniff analyze`, `scrub`,
    `unscrub`, and `diff` all produce byte-identical output to before this
    change.
  - `OtError::PrivacyLeak { kind, message }` is now
    `OtError::Privacy(#[from] otsniff_privacy::PrivacyError)`, mirroring the
    existing `OtError::Segmentation` wrapper pattern. The error message
    shape (`"privacy invariant tripped: ..."`) and exit code (75) are
    unchanged.
  - This exists to support a planned companion tool ("otsniff-hunt") that
    will reuse the same never-see-real-identifiers guarantee over data from
    sources otsniff itself never touches, without forking or duplicating
    the verified privacy core.
