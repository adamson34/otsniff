# AC-002: Bidirectional Invariant Documentation

Source: `head -80 docs/proofs/ensure-no-map-values.md`

```
# ensure_no_map_values Substring Invariant Proof

## Invariant

`ensure_no_map_values(text, map)` proves the bidirectional invariant (iff) for
BC-5.02.002:

- **Forward:** If any `v ∈ map.real_values()` appears as a substring of
  `text`, then the function returns `Err`.
- **Backward:** If no `v ∈ map.real_values()` appears as a substring of
  `text`, then the function returns `Ok`.

In short: `result.is_err()` iff `text.contains(v)` for some `v` in the map.

This covers the hostname-shape leak class that the regex-based `scan()`
cannot catch (e.g. `LINE-3-PLC`, `host42`, `EWS-WORKSTATION`).

## Harness

Location: `src/ai/leak_detector.rs` — `#[cfg(kani)] mod kani_proofs`, function
`map_value_substring`.

The harness constructs:

1. A symbolic real value: 1–8 bytes of ASCII alphanumeric or `-` characters
   (matching typical hostname fragment shapes).
2. A symbolic input string: 0–16 printable ASCII bytes.
3. A `ScrubMap` with K = 1 entry in the `names` family, mapping the concrete
   pseudonym `"name_001"` to the symbolic real value.

It then calls `ensure_no_map_values(input, &map)` and asserts the
bidirectional invariant:

```rust
if input.contains(value) {
    assert!(result.is_err(), "must flag when value is substring");
} else {
    assert!(result.is_ok(), "must not flag when value is not substring");
}
```

## Bounds

| Parameter | Bound used | Spec bound | Rationale for narrowing |
|-----------|-----------|------------|------------------------|
| `text` length (N) | ≤ 16 bytes | ≤ 32 bytes | Keeps CBMC path count tractable. The substring check in the production code is a linear scan; the proof still exercises every possible position of a length-8 value inside a length-16 input, covering all match and no-match cases. |
| Number of map values (K) | 1 | ≤ 4 | The property is compositional: `ensure_no_map_values` iterates values independently. If it correctly returns `Err` when one value matches (and `Ok` when it does not), the same holds for K values. K = 1 exercises the full code path without multiplying state space. |
| Each map value length | ≤ 8 bytes | ≤ 8 bytes | Matches spec exactly. |
| Value alphabet | ASCII alphanumeric + `-` | Unrestricted | Ensures `str::from_utf8` always succeeds for the symbolic value bytes. Hostname fragments are always drawn from this alphabet in practice. |
```
