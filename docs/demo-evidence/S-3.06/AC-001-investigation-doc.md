# AC-001 Evidence: Investigation Note Exists With All Required Sections

**Acceptance criterion:** `docs/ci-investigations/2026-05-macos-rustup-flake.md`
committed, contains all required sections, contains zero TODOs.

---

## Command: `head -100 docs/ci-investigations/2026-05-macos-rustup-flake.md`

```
---
document_type: ci-investigation
story_id: S-3.06
status: complete
timestamp: 2026-05-15T00:00:00Z
---

# macOS CI Flake: rustup-init invoked instead of cargo proxy

## Summary

Beginning 2026-05-13, the `Test (macos-14)` CI job began intermittently failing with
`error: unexpected argument 'test' found / Usage: rustup-init[EXE]` — the `cargo`
proxy shim at `$HOME/.cargo/bin/cargo` had been silently replaced with `rustup-init`
bytes by `Swatinem/rust-cache@v2`'s cache restore step. PR runs passed because they
started with an empty cache; develop pushes that hit the populated cache failed every
time. Four attempted mitigations were tried across PRs #60–#63: pinning the runner
image to macos-14 (no effect), inserting a PATH guard step (Swatinem's subsequent
cache restore re-corrupted the binaries), calling cargo by its absolute path (the
absolute path also resolved to rustup-init bytes), and running `rustup default stable`
to repair the proxy (rustup itself was also corrupted — no in-band repair is possible).
Root cause is confirmed: `Swatinem/rust-cache@v2` captures `$HOME/.cargo/bin/` during
a degraded run and, once that bad cache key is stored, every subsequent develop push
that matches the cache key has all cargo/rustc/rustup/rustdoc binaries overwritten with
the `rustup-init` installer binary. The chosen remediation (S-3.06 option b'') is to
drop the `Swatinem/rust-cache@v2` step from the macOS test job only, eliminating the
cache-corruption vector at the cost of approximately 90 seconds of cold compile time
per macOS CI run.

## Flake occurrences

| Date | Trigger (PR / develop push) | Run ID | Runner image label |
|------|-----------------------------|--------|--------------------|
| 2026-05-14 | develop push after PR #60 merge (SHA 547f644) | 25871621499 | macos-14-arm64 v20260512.0058.1 |
| 2026-05-14 | develop push after PR #61 merge (SHA 0dd2046) | 25872997013 | macos-14-arm64 v20260512.0058.1 |
| 2026-05-14 | develop push after PR #62 merge (SHA 2fe7e8c) | 25873171202 | macos-14-arm64 v20260512.0058.1 |
| 2026-05-14 | develop push after PR #65 merge (SHA 89168bd) | 25875075185 | macos-14-arm64 v20260512.0058.1 |

## Runner image correlation

The runner image label was `macos-14-arm64` version `20260512.0058.1` on every
failing run examined. All four failed runs used the identical image version; the
macOS 14 → 15 runner image transition is **not** the root cause. Attempt 1 (PR #60)
explicitly pinned `runs-on: macos-14` to test this hypothesis — the flake recurred
unchanged on the pinned image. The correlation with the macOS 14 → 15 transition is
**negative**: runner image version does not predict whether a run succeeds or fails.
The distinguishing factor is cache hit (develop pushes, which fail) versus cache miss
(PR runs against a fresh cache key, which pass).

## Upstream issue search

Searches run 2026-05-15:

- `gh search issues "Swatinem rust-cache rustup-init" --limit 5` — no relevant upstream
  issue found as of 2026-05-15. No open or closed issues in `Swatinem/rust-cache` match
  the specific symptom of cargo proxy binaries being replaced with rustup-init bytes.
- `gh search issues "macos cargo rustup-init unexpected argument test" --limit 5` — no
  relevant upstream issue found as of 2026-05-15. The symptom appears to be specific to
  a bad cache key created during a degraded initial toolchain install on macOS ARM64
  runners; no upstream bug report was found in `dtolnay/rust-toolchain`,
  `actions/runner-images`, or `rust-lang/rustup` that matches this failure mode exactly.

The absence of upstream reports suggests the bad cache content was produced by a
one-time degraded runner state unique to this repository's cache key, rather than a
systematic bug in any upstream action.

## Root cause hypothesis

`Swatinem/rust-cache@v2`'s macOS cache restore replaces every binary under
`$HOME/.cargo/bin/` (cargo, rustc, rustup, rustdoc) with `rustup-init` bytes, because
the cache content was captured during an earlier run where the toolchain proxy was in a
degraded state, and once the bad cache entry is stored, every subsequent run that hits
the same cache key restores the corrupted binaries.

## Chosen fix

Option (b'') — drop `Swatinem/rust-cache@v2` from the `test-macos` job only — was
chosen because it eliminates the cache-corruption vector entirely with a well-understood
trade-off (+90 seconds per macOS run for cold compile), while leaving caching intact
for all Linux jobs (clippy, test, msrv) where the corruption has never been observed.

## Rollback plan

If this fix introduces a different macOS regression, revert it with a single commit:

```
git revert <SHA-of-feat(S-3.06)-commit>
```

After reverting, the preferred next attempt is option (c) from AC-002: replace
`dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache@v2` with
`actions-rust-lang/setup-rust-toolchain@v1`, which manages its own caching strategy
and reportedly avoids this failure mode. Option (c) replaces both toolchain install and
caching in a single action swap, making regression attribution harder than option (b''),
which is why it was held as the fallback rather than the first choice.
```

---

## Command: `grep -c "^## " docs/ci-investigations/2026-05-macos-rustup-flake.md`

```
7
```

**Expected: 7+. Actual: 7. PASS.**

---

## Command: `grep -c "TODO" docs/ci-investigations/2026-05-macos-rustup-flake.md`

```
0
```

**Expected: 0. Actual: 0. PASS.**
