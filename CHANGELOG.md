# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **New workspace crate `crates/otsniff-privacy`** (ADR-0016): the pseudonym
  scrub/unscrub mechanics and the fail-closed leak detector, extracted so a
  planned companion tool ("otsniff-hunt") can reuse the same
  never-see-real-identifiers guarantee over data otsniff itself never
  touches, without forking or duplicating the verified privacy core.

### Changed

- **Internal refactor:** moved the pseudonym scrub/unscrub mechanics and
  the fail-closed leak detector into the new `crates/otsniff-privacy`
  (ADR-0016). `ScrubMap`, `scrub_text`/`unscrub_text`, `pseudonym_regex`,
  and `leak_detector::{scan, ensure_clean, ensure_no_map_values}` moved out
  of `src/scrub.rs` and `src/ai/leak_detector.rs` along with their Kani
  proofs and unit tests — not verbatim: return types now use the new
  crate's own `PrivacyError` instead of `OtError`, and
  `is_canonical_pseudonym`, `max_index`, `merge_family`, and
  `pseudonym_regex` widened from private to `pub` (and
  `parse_pseudonym_index` from private to `pub(crate)`) so otsniff's call
  sites (and a future otsniff-hunt) can reach them across the crate
  boundary. `otsniff`'s own `src/scrub.rs` keeps
  only the population functions (`build_map`, `build_map_at`, `merge_map`)
  that walk otsniff's `Observations` capture model.
  - No user-facing or CLI behavior change: `otsniff analyze`, `scrub`,
    `unscrub`, and `diff` all produce byte-identical output to before this
    change.
  - `OtError::PrivacyLeak { kind, message }` is now
    `OtError::Privacy(otsniff_privacy::PrivacyError)`, following the same
    wrapping shape as the existing `OtError::Segmentation` variant (an
    `OtError` variant wrapping the sub-crate's own error type), for the
    fail-closed leak-detector trip specifically. Unlike `Segmentation`,
    which derives `#[from]`, `Privacy` uses a hand-written `From` impl —
    `#[from]` also derives `#[source]`, which would have added a new
    `caused by: ...` stderr line (main.rs walks `Error::source()`) that
    didn't exist pre-extraction, violating the "no observable behavior
    change" constraint. The error message shape
    (`"privacy invariant tripped: ..."`) and exit code (75) are unchanged
    for that path. See ADR-0016's "Decision refinement" section.
  - `ScrubMap::validate()` / `merge_family()`'s structural map-corruption
    errors (empty pseudonym, empty real value, non-canonical pseudonym,
    duplicate real value, pseudonym collision) are a distinct
    `otsniff_privacy::PrivacyError::MapCorrupt` variant, routed back to
    `OtError::Parse` by that same hand-written `From` impl — preserving the
    pre-extraction exit code (70) and `"pcap parse error: ..."` message
    prefix for that class of error exactly, rather than folding it into the
    75/"privacy invariant tripped" shape above.
