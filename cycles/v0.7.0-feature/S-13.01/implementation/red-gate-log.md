# Red-Gate Log — S-13.01 (Extract privacy/scrub layer into `crates/otsniff-privacy`)

Branch: `feature/S-13.01-otsniff-privacy-crate`
TDD mode: strict (refactor of formally-verified code — moved tests must go red
against stubs before implementation, even though no new behavior is introduced).

## Pre-flight: ADR-0016 sync gap (found and fixed before Step 1)

The story's spec basis, ADR-0016, existed only on a local, unpushed branch
(`feat/otsniff-privacy-crate`, commit `f825247`) — never opened as a PR, never
merged to `develop`. The S-13.01 worktree/branch had been created off a
`develop` that predated it. Also found: `develop` itself had a pre-existing
`clippy::useless_format` failure (unrelated to this story) blocking all CI.

Fixed via two PRs, both merged (admin-merge, CI fully green,
`enforce_admins: false` on this repo):
- #163 `fix(ci): clear useless_format clippy lint blocking develop`
- #162 `docs(adr): ADR-0016 + roadmap entry for otsniff-privacy crate extraction (P1-14)`

S-13.01 worktree fast-forwarded to the corrected `develop` tip (`23223e4`)
before any stub/test work began.

## Commit ordering (`git log develop..HEAD` on `feature/S-13.01-otsniff-privacy-crate`)

| Order | Commit | Kind |
|---|---|---|
| 1 | `a7053b4` | feat(S-13.01): add otsniff-privacy crate stubs |
| 2 | `86caafa` | fix(S-13.01): widen merge_family/max_index visibility for cross-crate calls (AC-004) |
| 3 | `51655ca` | test(S-13.01): add failing tests for moved scrub/leak-detector mechanics (Red Gate) |

## Stubs created (`crates/otsniff-privacy`, all `todo!()` bodies)

- `scrub.rs`: `ScrubMap` (struct/fields real, kept), `len`, `is_empty`,
  `validate`, `real_values`, `scrub_text`, `unscrub_text`, `pseudonym_regex`,
  `merge_family` (`pub`), `max_index` (`pub`), `is_canonical_pseudonym` (`pub`),
  `parse_pseudonym_index` (`pub(crate)`); S-4.01 round-trip Kani proof module
  copied verbatim (bounds unchanged).
- `leak_detector.rs`: `scan`, `ensure_clean` / `ensure_no_map_values` (return
  `PrivacyError`, not `OtError` — the one deliberate signature change per
  AC-003), `Leak`, `LeakKind` kept as real definitions; 4 Kani harness stubs
  (`leak_regex_ipv4`, `leak_regex_ipv6`, `leak_regex_mac`,
  `map_value_substring`) copied verbatim.
- `error.rs`: `PrivacyError::Leak { kind, message }` (thiserror) — complete,
  no stubbing needed (no business logic).
- Workspace `Cargo.toml`: `crates/otsniff-privacy` added to `members`; root
  package depends on it via path.

**Verification finding during stub review:** `merge_family`/`max_index` were
initially `pub(crate)`, which would have blocked otsniff root's `src/scrub.rs`
from calling them across the crate boundary — AC-004 explicitly requires that
call. Caught independently (not self-reported by the stub agent), sent back
for a fix; verified `pub` after the fix (commit `86caafa`).

## Red Gate verification (independently re-run by orchestrator)

```
cargo test -p otsniff-privacy
test result: FAILED. 0 passed; 13 failed; 0 ignored; 0 measured; 0 filtered out
```

All 13 failures are `todo!()` panics (`not yet implemented: BC-5.38.001: ...`),
none are build errors or unrelated assertion failures:

- 6 scrub-mechanics tests (`test_bc_5_03_001_load_rejects_map_with_empty_pseudonym`,
  `test_f_w1_002_pseudonym_regex_rejects_hex_only_suffix`,
  `test_f_w1_003_validate_rejects_duplicate_real_values_same_family`,
  `test_f_w1_003_validate_rejects_duplicate_real_values_cross_family`,
  `test_f_w1_003_validate_accepts_unique_real_values`,
  `test_f_w1_002_decimal_pseudonym_not_in_map_is_still_unknown`)
- 7 leak-detector tests, moved in full (`flags_ipv4_in_otherwise_clean_text`,
  `flags_mac_in_text`, `flags_ipv6_in_text`, `does_not_flag_pseudonyms`,
  `does_not_flag_normal_prose`, `ensure_clean_returns_descriptive_error`,
  `ensure_no_map_values_catches_hostname_leak_that_regex_misses`) — the last
  two double as the AC-003 regression tests (IPv4-leak diagnostic shape,
  hostname-leak-via-map-value), adapted to assert on `PrivacyError`'s own
  `Display` output instead of `OtError`'s wrapped message (this crate has no
  `OtError`; the wrapper-shape assertion — `"privacy invariant tripped: "`
  prefix, exit code 75 — is otsniff-root's responsibility once
  `OtError::Privacy(#[from] ...)` exists, later in this story).

No direct unit test exists for `merge_family`/`max_index`/`is_canonical_pseudonym`/
`parse_pseudonym_index` in isolation in the original file — they were only
covered transitively via `merge_map`-based tests, which stay in otsniff root
per AC-004 (population logic). That transitive coverage is unaffected by this
move.

`cargo check --workspace` — clean (only expected unused-stub/dead-code
warnings). `src/scrub.rs` and `src/ai/leak_detector.rs` at the repo root
confirmed untouched by `git status`.

## Regression check

| Existing tests | Status |
|---|---|
| otsniff root crate (`cargo check --workspace`) | unaffected, still checks clean |
| otsniff-privacy (new) | 13/13 red as expected, 0 unexpected failures |

## Hand-off to implementer

- Story ready for TDD implementation: S-13.01.
- Move the real bodies of `ScrubMap`'s methods, `scrub_text`/`unscrub_text`/
  `pseudonym_regex`, `merge_family`/`max_index`/`is_canonical_pseudonym`/
  `parse_pseudonym_index`, and `leak_detector::{scan, ensure_clean,
  ensure_no_map_values}` from the originals into the stubs one test at a time.
- Move both Kani proof modules' real proof logic next (S-4.01 round-trip,
  S-4.02/03/04 leak-detector harnesses), preserving `#[kani::unwind(N)]`
  bounds exactly (do not "clean up" — story explicitly warns against this).
- Then: define `OtError::Privacy(#[from] otsniff_privacy::PrivacyError)` in
  `src/error.rs` (replacing `PrivacyLeak{..}`), trim `src/scrub.rs` to
  `build_map`/`build_map_at`/`merge_map` only, delete `src/ai/leak_detector.rs`,
  update every call site (`ai/mod.rs`, `cli.rs`, `audit.rs`,
  `findings/augmented.rs`, `kani_proofs.rs`, `tests/snapshot.rs`) to
  `otsniff_privacy::*` paths, then `cargo insta review` for zero snapshot
  diffs (AC-005) and update `kani.yml` / `.cargo-mutants.toml` paths
  (EC-003/EC-004).
