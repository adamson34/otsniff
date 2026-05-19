# Scrub Round-Trip Proof

Formal verification of the privacy invariant: `unscrub(scrub(s, m), m) == s`
for any bounded input string `s` and any deterministic pseudonym map `m`.

Traces to: BC-5.01.003, ADR-0006, S-4.01.

## Harness

TODO (S-4.01): Document the final harness location and function name once
`scrub_roundtrip_bounded()` in `src/scrub.rs` is implemented.

```rust
// Placeholder — see src/scrub.rs #[cfg(kani)] mod kani_proofs
#[kani::proof]
fn scrub_roundtrip_bounded() { todo!() }
```

## Bounds

TODO (S-4.01): Fill in chosen bounds after tuning.

| Bound | Symbol | Initial value | Rationale |
|-------|--------|--------------|-----------|
| Max input length (bytes) | N | 32 | TODO |
| Max map entries | K | 4 | TODO |

Initial values (N = 32, K = 4) are per AC-001. Tune until proof completes
in < 20 min on the CI runner (ubuntu-latest).

## Rationale

TODO (S-4.01): Explain why these bounds constitute adequate evidence for
the unbounded claim. Reference any known limitations (e.g., non-UTF8 bytes
don't reach `scrub_text` because it operates on `&str` — see EC-003 in the
story).

## How to Run

```bash
# Install cargo-kani (one-time):
cargo install --locked kani-verifier
cargo kani setup

# Run the proof:
cargo kani --harness scrub_roundtrip_bounded
```

CI runs this weekly via `.github/workflows/kani.yml` (Sunday 06:00 UTC).
Manual dispatch is also available via the GitHub Actions UI.
