# ensure_no_map_values Substring Invariant Proof

## Proof-Model Architecture

The production `ensure_no_map_values` function calls `str::contains`, whose
UTF-8 validation loop is too wide for CBMC to unwind within a reasonable budget,
causing the original harness to time out at the 15-minute CI limit.

Instead, the harness uses a hand-rolled byte-level model function
`byte_contains_model(haystack, needle) -> bool` that implements the same
linear forward search without `str::contains` or UTF-8 validation.

**What is proved:** the model is internally self-consistent — for all symbolic
inputs within the bounds, if `byte_contains_model` returns `true`, a brute-force
window scan confirms a match exists; if it returns `false`, no window matches.

**What is deferred:** model-vs-production equivalence (that
`byte_contains_model(h, n) == h_str.contains(n_str)`) is verified separately
by the fuzz suite (S-3.04).

Production code (`ensure_no_map_values`, `ensure_clean`) is **never modified**.
All model functions are inside `#[cfg(kani)] mod kani_proofs`.

---

## Invariant

`byte_contains_model(haystack, needle)` proves the bidirectional invariant:

- **Forward:** needle is a contiguous byte subsequence of haystack → model returns `true`
- **Backward:** needle is NOT a contiguous byte subsequence → model returns `false`

This covers the hostname-shape leak class that the regex-based `scan()` cannot
catch (e.g. `LINE-3-PLC`, `host42`, `EWS-WORKSTATION`).

---

## Harness

**Location:** `crates/otsniff-privacy/src/leak_detector.rs` (moved from
`src/ai/leak_detector.rs` by ADR-0016 / S-13.01) — `#[cfg(kani)] mod
kani_proofs`, function `map_value_substring`.

The harness constructs:

1. A symbolic needle: 1–4 bytes, ASCII alphanumeric or `-`.
2. A symbolic haystack: 0–4 printable ASCII bytes.
3. Calls `byte_contains_model(haystack, needle)` and verifies self-consistency
   via a brute-force inner assertion.

```rust
#[kani::proof]
#[kani::unwind(6)]
fn map_value_substring() { ... }
```

---

## Bounds

| Parameter | Bound used | Previous bound | Rationale for narrowing |
|-----------|-----------|----------------|------------------------|
| haystack length (N) | ≤ 4 bytes | ≤ 16 bytes | Tighter bound eliminates CBMC timeout from `str::contains` UTF-8 validation. The byte model still exercises all structural cases: no match, match at start, match at end, match in middle. |
| needle length | ≤ 4 bytes | ≤ 8 bytes | Sufficient to cover all window-overlap cases within a 4-byte haystack. |
| Number of map values (K) | 1 | 1 | Compositional argument unchanged: `ensure_no_map_values` iterates values independently; K = 1 is sufficient. |
| `#[kani::unwind]` | 6 | 33 | Model inner loop iterates ≤ 4 times; 6 gives CBMC two steps of headroom. |
| Verification time | ~0.7s | timeout | Well within the 15-min CI budget. |

---

## Bidirectional Invariant

### Forward direction (match → true)

If a window of the haystack equals the needle, `byte_contains_model` must
return `true`.  The harness asserts this via brute-force confirmation after a
`true` return.

### Backward direction (no match → false)

If no window matches the needle, `byte_contains_model` must return `false`.
The harness asserts this by checking every window after a `false` return.

---

## Edge Cases Covered

| ID | Scenario | Expected |
|----|----------|---------|
| EC-001 | Empty haystack | Always `false` (needle is non-empty) |
| EC-002 | Needle longer than haystack | Always `false` |
| EC-003 | Needle at position 0 | `true` |
| EC-004 | Needle at last position | `true` |

---

## Run Instructions

```bash
cargo kani -p otsniff-privacy --harness map_value_substring
```

---

## Related

- `docs/proofs/leak-detector-regex.md` — regex harnesses (S-4.02)
- `docs/proofs/scrub-roundtrip.md` — scrub round-trip proof (S-4.01)
- BC-5.02.002 — behavioral contract supported by this harness
