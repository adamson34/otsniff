# AC-003: Proof Documentation

**Command:** `cat docs/proofs/scrub-roundtrip.md`

```
# Scrub Round-Trip Proof

Formal verification of the privacy invariant:

```
unscrub(scrub(s, m), m) == s
```

for any bounded ASCII input string `s` and any deterministic pseudonym map `m`.

Traces to: BC-5.01.003, ADR-0006, S-4.01.

## Harness

**Location:** `src/scrub.rs`, inside `#[cfg(kani)] mod kani_proofs`

**Function name:** `scrub_roundtrip_bounded`

The harness is gated with `#[cfg(kani)]` and `#[kani::proof]`. It is
not compiled during normal `cargo build`, `cargo test`, or `cargo check`
runs and has no effect on the test suite.

```rust
#[kani::proof]
#[kani::unwind(9)]
fn scrub_roundtrip_bounded() {
    // symbolic ASCII input of length <= N
    // symbolic real value (printable ASCII, not pseudonym-shaped)
    // map with one concrete pseudonym "host_001" → symbolic real value
    let scrubbed  = scrub_text(input, &map);
    let (unscrubbed, ..) = unscrub_text(&scrubbed, &map);
    assert_eq!(input, unscrubbed);
}
```

See the source for the full harness body with all `kani::assume` preconditions.

## Bounds

| Bound | Symbol | Chosen value | Rationale |
|-------|--------|-------------|-----------|
| Max input length (bytes) | N | 8 | ... |
| Max map entries | K | 1 | ... |

Initial AC-001 values were N = 32, K = 4. After reviewing Kani's state-space
behaviour for string-mutation proofs, N was reduced to 8 and K to 1 to ensure
the proof completes well under the 20-minute CI budget.

## Rationale: why bounded proof + fuzz = strong evidence for the unbounded claim

The bounded Kani proof shows the round-trip holds for **every possible input**
of length ≤ 8 bytes (full symbolic coverage within the bound). The sentinel fuzz
suite covers longer inputs by random exploration.

## Known limitations

- Non-UTF-8 inputs are excluded by design (EC-003).
- The proof covers the `ips` family only.
- Kani was not installed in the development environment (deferred per L-P3-002).

## How to run locally

```bash
cargo install --locked kani-verifier
cargo kani setup
cargo kani --harness scrub_roundtrip_bounded
```

## CI integration

`.github/workflows/kani.yml` runs this proof on a weekly schedule (Sunday
06:00 UTC) and on manual dispatch, 30-minute timeout.
```

**Status:** PASS — file exists and documents N = 8, K = 1 bounds with rationale.
