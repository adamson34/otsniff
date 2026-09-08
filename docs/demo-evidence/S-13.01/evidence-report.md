# Evidence Report: S-13.01

**Story:** S-13.01 — Extract privacy/scrub layer into `crates/otsniff-privacy`
**Story ID:** S-13.01
**Behavioral Contracts:** BC-5.01.001, BC-5.01.002, BC-5.01.003, BC-5.01.004, BC-5.02.001, BC-5.02.002, BC-5.02.003, BC-5.03.001
**Worktree HEAD SHA:** 29461e0fb4c210419168437e6aab07e2533ad651
**Date:** 2026-09-08
**Branch:** feature/S-13.01-otsniff-privacy-crate

## Non-standard recording note

Like S-3.03/S-3.06/S-4.01, this is a pure internal refactor with
`tdd_mode: strict` but no CLI surface change and no new user-facing
behavior — ADR-0016 explicitly constrains this story to zero observable
behavior change. VHS/Playwright demo recording does not apply (there is
nothing new to show a user); the deliverable is a crate boundary, moved
formally-verified code, and an unchanged CLI/output surface. Evidence
consists of captured command output proving the acceptance criteria hold
against the actual worktree, following the same pattern as
`docs/demo-evidence/S-4.01/` (Kani proof story), `docs/demo-evidence/S-3.03/`
(mutation-testing config story), and `docs/demo-evidence/S-3.06/` (CI
path-fix story).

## AC Coverage

| AC | Description | Evidence File | Result |
|----|-------------|---------------|--------|
| AC-001 | `otsniff-privacy` crate exists with moved mechanics; deps limited to regex/serde/chrono/sha2/thiserror | `dependency-tree.md` | PASS |
| AC-001 | Scrub round-trip Kani proofs move verbatim and still prove | `acceptance-script-run.md` (structural), `kani-proof-verification.md` (both scrub harnesses actually run) | PASS |
| AC-002 | `leak_detector` moves with its proofs; error type is `PrivacyError`, not `OtError` | `acceptance-script-run.md` (structural), `kani-proof-verification.md` (all 4 leak-detector harnesses actually run) | PASS (2 pre-existing, unrelated grep-heuristic failures — see note below) |
| AC-003 | Error boundary preserves message shape and exit code (`Leak` → exit 75, `MapCorrupt` → exit 70) | `cli-behavior-check.md` | PASS |
| AC-004 | otsniff's population logic and all call sites compile and pass; zero new warnings | `test-suite-run.md` | PASS |
| AC-005 | No observable behavior change; full test suite passes with same function count | `test-suite-run.md`, `cli-behavior-check.md` | PASS |

## Summary of captured evidence

1. **`cargo tree -p otsniff-privacy --edges normal`** (`dependency-tree.md`)
   — confirms the crate's only direct dependencies are `chrono`, `regex`,
   `serde`, `sha2`, `thiserror`, with no edge to `otsniff` or `zonewarden`
   and none of the explicitly forbidden crates (`askama`, `pcap-parser`,
   `etherparse`, `clap`, `ipnet`, `pulldown-cmark`, `serde_norway`)
   anywhere in the transitive closure. Directly demonstrates the Forbidden
   Dependencies contract (AC-001).

2. **Kani-proof structural acceptance scripts** (`acceptance-script-run.md`)
   — re-ran `scripts/check-s-4-01-acceptance.sh` (8/8 PASS),
   `scripts/check-s-4-02-acceptance.sh` (11/12 PASS), and
   `scripts/check-s-4-03-acceptance.sh` (6/7 PASS) against the
   post-extraction tree. All harness declarations, `#[cfg(kani)]` gates,
   proof docs, and CI wiring resolve correctly at the new
   `crates/otsniff-privacy/src/...` paths. The two failing checks
   (`AC-001f` in check-s-4-02, `AC-001c` in check-s-4-03) are a known,
   pre-existing grep-heuristic mismatch — the checker scripts look for a
   literal call to `scan()`/`ensure_clean()`/`ensure_no_map_values()`
   inside the `#[cfg(kani)]` block, but the harnesses correctly model the
   underlying byte-level logic directly per the documented proof-model
   architecture (Kani/CBMC cannot unwind `regex`'s NFA/DFA). This failure
   is identical on `develop` prior to this story's changes and is not a
   regression introduced by the crate extraction.

3. **Kani proof execution, all 6 moved harnesses** (`kani-proof-verification.md`)
   — actually ran all 6 harnesses that moved under ADR-0016
   (`cargo-kani 0.67.0` is available in this environment):
   `scrub_roundtrip_bounded` and `scrub_roundtrip_single_replacement`
   (AC-001), plus `leak_regex_ipv4`, `leak_regex_ipv6`, `leak_regex_mac`,
   and `map_value_substring` (AC-002). Every harness reports
   `VERIFICATION:- SUCCESSFUL` with 0 failed checks, and every check's
   location points into `crates/otsniff-privacy/src/{scrub,leak_detector}.rs`
   (or the standard library, for the two harnesses that call `u8::is_ascii_*`
   helpers), confirming each harness runs against the moved code, not the
   old `src/scrub.rs` / `src/ai/leak_detector.rs` locations.

4. **Build / test / lint / format** (`test-suite-run.md`) —
   `cargo build --workspace` is clean with zero warnings.
   `cargo test --workspace` reports **678 passed, 0 failed** across all
   33 test binaries in the three-member workspace (`otsniff`,
   `otsniff-privacy`, `zonewarden`). `otsniff-privacy`'s own lib target has
   17 total tests: 13 relocated (6 from `src/scrub.rs`, 7 from
   `src/ai/leak_detector.rs`) plus 4 net-new `test_f_002_*` regression
   tests added during review. `cargo clippy --workspace --all-targets
   --all-features -- -D warnings` and `cargo fmt --all -- --check` both
   exit clean with no output.

5. **Live CLI map-corruption check** (`cli-behavior-check.md`) —
   constructed a scrub map JSON with an empty pseudonym key and ran
   `cargo run --quiet -- unscrub --map <file> /dev/null`. Output:
   `otsniff: pcap parse error: scrub map has empty pseudonym key for real
   value '10.0.0.1'; the map is corrupted (EC-001). Regenerate the map
   with \`otsniff scrub\`.`, exit code **70**. Confirms
   `PrivacyError::MapCorrupt` still routes through `OtError::Parse`
   (exit 70) post-extraction — distinct from the leak detector's
   `PrivacyError::Leak` → `OtError::Privacy` path (exit 75) — exercising
   AC-003's error-boundary wrapper live through the compiled binary
   rather than only via unit tests.

## Files

- `dependency-tree.md` — `cargo tree -p otsniff-privacy` output + analysis (AC-001)
- `acceptance-script-run.md` — S-4.01/S-4.02/S-4.03 acceptance script output against the moved code (AC-001, AC-002)
- `kani-proof-verification.md` — actual `cargo kani` execution of all 6 moved harnesses (AC-001, AC-002)
- `test-suite-run.md` — `cargo build`/`cargo test`/`cargo clippy`/`cargo fmt` output (AC-004, AC-005)
- `cli-behavior-check.md` — live CLI map-corruption check proving the error boundary is unchanged (AC-003, AC-005)
- `evidence-report.md` — this file
