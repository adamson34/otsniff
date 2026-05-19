# ensure_no_map_values Substring Invariant Proof

## Invariant

`ensure_no_map_values(text, map)` proves the bidirectional invariant for
BC-5.02.002:

- **Forward:** If any `v ∈ map.real_values()` appears as a substring of
  `text`, then the function returns `Err`.
- **Backward:** If no `v ∈ map.real_values()` appears as a substring of
  `text`, then the function returns `Ok`.

This covers the hostname-shape leak class that the regex-based `scan()`
cannot catch (e.g. `LINE-3-PLC`, `host42`, `EWS-WORKSTATION`).

## Harness

<!-- TODO: document the harness body once the proof is implemented -->

Location: `src/ai/leak_detector.rs` — `#[cfg(kani)] mod kani_proofs`, function
`map_value_substring`.

```rust
#[kani::proof]
fn map_value_substring() {
    // TODO: implement symbolic harness
    todo!()
}
```

## Bounds

<!-- TODO: document bound choices and rationale -->

| Parameter | Bound | Rationale |
|-----------|-------|-----------|
| `text` length | ≤ 32 bytes | TODO |
| Number of map values | ≤ 4 | TODO |
| Each map value length | ≤ 8 bytes | TODO |

## Bidirectional Invariant

<!-- TODO: expand proof sketch for each direction -->

### Forward direction (leak → Err)

TODO

### Backward direction (no leak → Ok)

TODO

## Edge Cases Covered

| ID | Scenario | Expected |
|----|----------|---------|
| EC-001 | Empty map | Always `Ok` |
| EC-002 | Empty input | Always `Ok` (no value can be a substring of empty string) |
| EC-003 | Map value is empty string | Treated as no-match (skipped by implementation guard) |

## Run Instructions

<!-- TODO: update once cargo-kani is available in the dev environment -->

```bash
cargo kani --harness map_value_substring
```

This harness also runs in CI via `.github/workflows/kani.yml` on every Sunday
at 06:00 UTC and on manual `workflow_dispatch`.

## Related

- `docs/proofs/leak-detector-regex.md` — regex harnesses (S-4.02)
- `docs/proofs/scrub-roundtrip.md` — scrub round-trip proof (S-4.01)
- BC-5.02.002 — behavioral contract proved by this harness
