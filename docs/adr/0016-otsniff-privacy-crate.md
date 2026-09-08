# ADR-0016: Extract the privacy/scrub layer into `crates/otsniff-privacy`

## Status
Proposed.

## Context
otsniff's AI-assisted triage flow (ADR-0006, ADR-0007) depends on a fail-closed
privacy chokepoint between "derived artifacts" and "AI-bound bytes": `src/scrub.rs`
mints stable pseudonyms for every observed IP/MAC/hostname and substitutes them
into a rendered report before it can reach an LLM, and `src/ai/leak_detector.rs`
is the independent kill switch that refuses to let anything identifier-shaped
through even if the scrub layer has a bug. Both are load-bearing and heavily
verified: ~40 tests, the round-trip Kani proof (S-4.01), the leak-detector regex
Kani proofs (S-4.02), and the composed-invariant proof (S-4.04) all sit on top
of this code, and `OtError::PrivacyLeak` (exit code 75) is a stable, scripted-against
contract (F-ADV-P2-004, F-ADV-P2-007).

We are now building a second, separate product — a companion AI-powered OT
threat-hunting tool ("otsniff-hunt") that ingests asset/alert data from sources
otsniff never touches (Claroty and similar platform APIs, threat feeds, otsniff's
own JSON output) and needs to hand that data to an LLM under the same
never-see-real-identifiers guarantee. Per the "what would a normal dev do"
discussion, otsniff-hunt is not a separate repo — it lands as additional
workspace crates inside this repo, the same pattern ADR-0013 established for
`crates/zonewarden`. That means the privacy/scrub mechanics need to be callable
from a second crate that has no `Observations`/`HostObs` capture model at all.

Looking at the actual code, `scrub.rs` already splits cleanly into two halves:

- **Population** (`build_map`/`build_map_at`/`merge_map`): walks otsniff's
  `Observations`/`HostObs` capture model to *discover* identifiers. This is
  otsniff-specific — otsniff-hunt will discover identifiers from a completely
  different shape of input (API responses, JSON, feed records) and needs its
  own population logic per source.
- **Mechanics** (everything else): `ScrubMap` the data structure,
  `scrub_text`/`unscrub_text`, `pseudonym_regex`, and the pseudonym-counter
  internals (`merge_family`/`max_index`/`is_canonical_pseudonym`) are pure
  functions over `BTreeMap<String, String>` with no otsniff-specific
  dependency. Likewise `leak_detector::scan`/`ensure_clean`/`ensure_no_map_values`
  are pure text-scanning functions that only depend on `ScrubMap`, not on
  `Observations`.

This is structurally the same shape of decision ADR-0013 already made for
`zonewarden`: a formally-verified pure core that a second consumer needs,
extracted as a workspace crate (not a plain `src/` module) specifically so the
enforced no-I/O boundary that the Kani proofs depend on survives the move.

## Decision
Extract the mechanics half of the privacy layer into a new workspace crate,
`crates/otsniff-privacy`, and leave the population half in otsniff's `src/`.

**Moves to `crates/otsniff-privacy`:**
- `ScrubMap` (struct + its impl: `len`, `is_empty`, `validate`, `real_values`, …)
- `scrub_text`, `unscrub_text`, `pseudonym_regex`
- `merge_family`, `max_index`, `is_canonical_pseudonym`, `parse_pseudonym_index`
- `leak_detector::{scan, ensure_clean, ensure_no_map_values, Leak, LeakKind}`
- Every test currently exercising the above, and both Kani proof modules
  (`scrub.rs`'s round-trip harness and `leak_detector.rs`'s four regex/map-value
  harnesses) — the harnesses move with the code they prove.

**Stays in otsniff's `src/`:**
- `build_map` / `build_map_at` / `merge_map` — these are the only functions that
  touch `Observations`/`HostObs`. otsniff-hunt gets its own population functions
  over its own source types; only the `ScrubMap` shape and the scrub/unscrub
  mechanics underneath are shared.
- `OtError` itself — used everywhere in otsniff, not privacy-specific.

**Error boundary:** `otsniff-privacy` gets its own small error type (e.g.
`PrivacyError`) covering what `OtError::PrivacyLeak` covers today. `OtError`
gains a wrapping variant, following the exact pattern already established for
`Segmentation(#[from] zonewarden::errors::ZonewardenError)`:

```rust
#[error("privacy invariant tripped: {0}")]
Privacy(#[from] otsniff_privacy::PrivacyError),
```

`exit_code()` keeps returning 75 for this variant, and the `Display` output must
still satisfy the existing tests' assertions (`.contains("privacy invariant
tripped")`, kind name present, hash-prefix present, raw value absent —
F-ADV-P2-007). Whether that means `PrivacyError`'s own `Display` produces the
full `"{kind}: {message}"` tail, or `OtError`'s wrapper formats it, is an
implementation detail for the story, not this ADR — the observable contract
(message shape + exit code) does not change.

**Dependencies:** `otsniff-privacy` depends on `regex`, `serde`, `chrono`,
`sha2`, `thiserror` (all already workspace dependencies at the otsniff-root
level; pin the same versions). It does not depend on otsniff or on
`zonewarden`.

## Rationale
- **Precedent already set.** ADR-0013 established that a formally-verified pure
  core gets a crate boundary, not a module boundary, specifically to keep the
  no-I/O guarantee the Kani proofs rely on enforceable by `cargo`'s dependency
  graph rather than by convention. The privacy layer has the identical shape:
  pure functions, Kani proofs, a second consumer that needs them.
- **The population/mechanics split is real, not cosmetic.** `build_map` requires
  `Observations`; nothing else in the module does. Drawing the boundary there
  means `otsniff-privacy` has zero otsniff-specific types in its public API,
  which is what actually makes it reusable by otsniff-hunt.
- **Preserves the verified surface exactly.** Every test and both proof harnesses
  move as-is; nothing about the scrub/unscrub round-trip, the leak-detector
  regexes, or the composed invariant needs to change to make the split work.
- **Cheaper than the alternative for a solo maintainer.** Publishing to
  crates.io or standing up a separate repo would add real coordination cost
  (version pinning, cross-repo CI) for a single internal consumer; a workspace
  crate gives the reuse without that overhead, same conclusion ADR-0013 reached
  for zonewarden.

## Module layout
```
otsniff/                              (host repo; unchanged root binary)
├── Cargo.toml                        [workspace] members += "crates/otsniff-privacy"
├── src/
│   ├── scrub.rs                      keeps build_map/build_map_at/merge_map only;
│   │                                 re-exports or thinly wraps otsniff_privacy
│   │                                 types for existing call sites
│   ├── ai/leak_detector.rs           removed — call sites use otsniff_privacy::leak_detector
│   └── error.rs                      OtError::Privacy(#[from] otsniff_privacy::PrivacyError)
│                                     replaces the inline PrivacyLeak variant
└── crates/
    ├── zonewarden/                   (unchanged, ADR-0013)
    └── otsniff-privacy/              ← new
        ├── src/
        │   ├── lib.rs
        │   ├── scrub.rs              ScrubMap, scrub_text, unscrub_text,
        │   │                         pseudonym_regex, merge_family, max_index,
        │   │                         is_canonical_pseudonym (+ Kani round-trip proof)
        │   ├── leak_detector.rs      scan, ensure_clean, ensure_no_map_values,
        │   │                         Leak, LeakKind (+ 4 Kani harnesses)
        │   └── error.rs              PrivacyError
        └── (existing ~40 tests move with their functions)
```

## Consequences
- otsniff grows from a two-member workspace (root + `zonewarden`) to a
  three-member workspace. CI (`ci.yml`, `mutants.yml`, `kani.yml`) picks up the
  new crate the same way it picked up `zonewarden` in ADR-0013.
- Every call site of `scrub::ScrubMap`, `scrub::scrub_text`/`unscrub_text`,
  and `ai::leak_detector::*` in `src/` (cli.rs, ai/mod.rs, findings/augmented.rs,
  audit.rs, kani_proofs.rs) needs its `use` paths updated to `otsniff_privacy::…`.
  This is a mechanical rename, not a behavior change.
- `OtError::PrivacyLeak { kind, message }` becomes `OtError::Privacy(PrivacyError)`.
  This is a breaking change to `OtError`'s public shape; nothing outside this
  crate constructs `OtError` variants directly today, so the blast radius is
  internal call sites plus the tests in `error.rs`/`leak_detector.rs` that match
  on it.
- The extraction must ship with `cargo test` and `cargo kani` both green on the
  moved code before anything else touches it — no observable behavior change is
  the acceptance bar, per the human's explicit constraint going in.
- otsniff-hunt (not yet started) can depend on `otsniff-privacy` directly once
  it exists; this ADR does not scope otsniff-hunt itself, only the shared crate
  it will consume.

## Alternatives considered
- **Leave it in `src/`, let otsniff-hunt depend on the otsniff binary crate.**
  Rejected: a binary crate's `src/` is not a library dependency target, and pulling
  in all of otsniff's CLI/parsing/report code just to reuse `scrub_text` is the
  wrong shape entirely.
- **Publish `otsniff-privacy` to crates.io.** Rejected for the same reason
  ADR-0013 rejected publishing zonewarden: single internal consumer, solo
  maintainer, no benefit over a workspace path dependency.
- **Move the whole `scrub.rs` module verbatim, including `build_map`/`merge_map`.**
  Rejected: would force `otsniff-privacy` to depend on otsniff's `Observations`
  type, defeating the point of extraction — otsniff-hunt has no `Observations`.
- **Keep `PrivacyLeak` as a flat variant on `OtError` and have the new crate
  return `Result<T, String>` or similar.** Rejected: loses the typed, matchable
  error surface (`kind`, `exit_code`) that F-ADV-P2-004 specifically introduced
  a distinct variant to provide; the `#[from]`-wrapper pattern is the existing,
  proven convention (`Segmentation`) for exactly this situation.
