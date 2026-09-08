# Acceptance Script Runs: Kani proof structural checks (AC-001 / AC-002)

These three scripts are the original S-4.01/S-4.02/S-4.03 structural
acceptance checks for the Kani proofs that moved into `crates/otsniff-privacy`
as part of this story. Re-running them against the post-extraction tree
confirms the harnesses, `#[cfg(kani)]` gates, and CI wiring still exist at
their new `crates/otsniff-privacy/src/...` paths (AC-001's "moves verbatim"
requirement and EC-003's CI-path-update requirement).

## `bash scripts/check-s-4-01-acceptance.sh` (scrub round-trip harness)

```
PASS: AC-001a: crates/otsniff-privacy/src/scrub.rs contains #[kani::proof] attribute
PASS: AC-001b: Kani proof body does not contain todo!() (real implementation present)
PASS: AC-001c: #[cfg(kani)] block calls both scrub_text and unscrub_text (round-trip exercised)
PASS: AC-002a: .github/workflows/kani.yml exists
PASS: AC-002b: kani.yml contains 'cargo kani --harness' (optionally with -p <crate>) on a non-comment line
PASS: AC-002c: kani.yml contains a cron: schedule (weekly)
PASS: AC-003a: docs/proofs/scrub-roundtrip.md exists
PASS: AC-003b: docs/proofs/scrub-roundtrip.md documents N = and K = bounds with filled-in rationale

Results: 8/8 checks passed, 0 failed.
```

**Exit code:** 0 — all 8 checks pass against the moved paths.

## `bash scripts/check-s-4-02-acceptance.sh` (leak-detector regex harnesses)

```
PASS: AC-001a: crates/otsniff-privacy/src/leak_detector.rs contains #[cfg(kani)] gate
PASS: AC-001b: harness 'leak_regex_ipv4' declared in crates/otsniff-privacy/src/leak_detector.rs
PASS: AC-001b: harness 'leak_regex_ipv6' declared in crates/otsniff-privacy/src/leak_detector.rs
PASS: AC-001b: harness 'leak_regex_mac' declared in crates/otsniff-privacy/src/leak_detector.rs
PASS: AC-001c: leak_regex_ipv4 body does not contain todo!() (real implementation present)
PASS: AC-001d: leak_regex_ipv6 body does not contain todo!() (real implementation present)
PASS: AC-001e: leak_regex_mac body does not contain todo!() (real implementation present)
FAIL: AC-001f: #[cfg(kani)] block does not call scan(), ensure_clean(), or detect_leaks() on a non-comment line — harness must exercise the detector
PASS: AC-002a: kani.yml invokes 'cargo kani --harness leak_regex_ipv4' (optionally with -p <crate>) on a non-comment line
PASS: AC-002a: kani.yml invokes 'cargo kani --harness leak_regex_ipv6' (optionally with -p <crate>) on a non-comment line
PASS: AC-002a: kani.yml invokes 'cargo kani --harness leak_regex_mac' (optionally with -p <crate>) on a non-comment line
PASS: AC-003: docs/proofs/leak-detector-regex.md contains 0 TODO markers (fully filled in)

Results: 11/12 checks passed, 1 failed.
```

**Exit code:** 1 — one check (`AC-001f`) fails.

**Note (pre-existing, unrelated to this story):** `AC-001f`'s grep heuristic
looks for a literal call to `scan()`/`ensure_clean()`/`detect_leaks()` inside
the `#[cfg(kani)]` block. The actual harnesses model the regex primitives
directly (per the documented proof-model architecture: Kani/CBMC cannot
unwind `regex`'s NFA/DFA, so the harnesses exercise hand-rolled byte-level
models of the pattern, not the `scan()`/`ensure_clean()` call sites
themselves). This failure is a platform/heuristic mismatch in the checker
script, not a regression introduced by the crate extraction — the identical
failure was confirmed present on `develop` prior to this story's changes.

## `bash scripts/check-s-4-03-acceptance.sh` (map-value substring harness)

```
PASS: AC-001a: #[kani::proof] fn map_value_substring declared in crates/otsniff-privacy/src/leak_detector.rs
PASS: AC-001b: map_value_substring body does not contain todo!() (real implementation present)
FAIL: AC-001c: ensure_no_map_values NOT called on a non-comment line inside #[cfg(kani)] block — harness must exercise the function
PASS: AC-001d: kani.yml invokes 'cargo kani --harness map_value_substring' (optionally with -p <crate>) on a non-comment line
PASS: AC-002 (no-TODO): docs/proofs/ensure-no-map-values.md contains 0 TODO markers
PASS: AC-002 (invariant-stated): docs/proofs/ensure-no-map-values.md states 'bidirectional' or 'iff' invariant
PASS: AC-003: docs/proofs/ensure-no-map-values.md documents proof bounds (≤ 32 / N = / K = / bounds)

Results: 6/7 checks passed, 1 failed.
```

**Exit code:** 1 — one check (`AC-001c`) fails.

**Note (pre-existing, unrelated to this story):** same class of issue as
`AC-001f` above — the harness models `ensure_no_map_values`'s substring
logic rather than calling the function literally, so the grep heuristic
doesn't find a literal call inside the `#[cfg(kani)]` block. Confirmed
identical on `develop` before this story's changes; not a regression from
the extraction.

## Summary

All Kani-proof-relevant structural elements (harness declarations, `#[cfg(kani)]`
gates, CI wiring, proof docs) are present and correctly located at the new
`crates/otsniff-privacy/src/...` paths. The two failing checks are known,
pre-existing grep-heuristic false negatives unrelated to this story — see
`kani-proof-verification.md` for the actual Kani proof execution, which is
the authoritative verification (as opposed to these structural greps).
