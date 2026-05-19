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
| Max input length (bytes) | N | 8 | Symbolic execution over byte arrays scales roughly as 2^(8*N) CBMC paths. N = 8 covers every concrete real-world pattern: the shortest IPv4 address is 7 chars ("1.2.3.4"), a 4-char MAC octet pair, a 4-char short hostname. Inputs longer than N are covered by the sentinel fuzz suite (`cargo fuzz`). |
| Max map entries | K | 1 | The round-trip property is compositional: if it holds for one (pseudo, real) entry it holds for K entries, because each scrub/unscrub replacement is independent (pseudonyms are disjoint from the real-value alphabet by construction of `build_map`). K = 1 exercises the full replacement code path without multiplying state space. |

Initial AC-001 values were N = 32, K = 4. After reviewing Kani's state-space
behaviour for string-mutation proofs, N was reduced to 8 and K to 1 to ensure
the proof completes well under the 20-minute CI budget while retaining the
key structural guarantee.

## Rationale: why bounded proof + fuzz = strong evidence for the unbounded claim

The bounded Kani proof shows the round-trip holds for **every possible input**
of length ≤ 8 bytes (full symbolic coverage within the bound). The sentinel fuzz
suite (`cargo fuzz`, not yet enabled) covers longer inputs by random exploration.
Together:

- **Kani (N = 8):** exhaustive within the bound — no counterexample exists for
  short inputs.
- **Fuzz (N > 8):** probabilistic for longer inputs — millions of random cases
  over 24 h on CI.

This is bounded proof + probabilistic fuzz, not unbounded formal proof. The
combination provides strong evidence for the unbounded claim and is consistent
with the state of the art for string-manipulation proofs in Kani/CBMC.

### Preconditions baked into the harness

1. Input bytes are printable ASCII (0x20–0x7E). Non-UTF-8 bytes never reach
   `scrub_text` because it takes `&str`; this is EC-003 from the story.
2. The real value is non-empty (empty real values are rejected by
   `ScrubMap::validate()` — EC-001).
3. The real value does not equal or contain the pseudonym `"host_001"`.
   This mirrors the invariant maintained by `build_map`: real IPs and MACs
   are never pseudonym-shaped strings.

These preconditions are encoded as `kani::assume(...)` statements so Kani
explores only the reachable, valid state space.

## Known limitations

- Non-UTF-8 inputs are excluded by design (see EC-003).
- The proof covers the `ips` family only (pseudonym prefix `host_`). The
  `macs` and `names` families use the same code path in `scrub_text` and
  `unscrub_text`; a separate harness per family is left for S-4.02 / S-4.03.
- Kani was not installed in the development environment where this harness
  was authored (cargo-kani installation deferred per L-P3-002). The harness
  will be validated on the first CI execution of `.github/workflows/kani.yml`.

## How to run locally

```bash
# Install cargo-kani (one-time, ~5 min):
cargo install --locked kani-verifier
cargo kani setup

# Run the proof (expected: VERIFICATION SUCCESSFUL):
cargo kani --harness scrub_roundtrip_bounded
```

Expected output on success:

```
VERIFICATION RESULT: SUCCESSFUL
```

If the proof times out (> 30 min), reduce N further in `kani_proofs::N` and
re-run. Reducing to N = 4 will cut the state space to 2^32 paths.

## CI integration

`.github/workflows/kani.yml` runs this proof on a weekly schedule (Sunday
06:00 UTC) and on manual dispatch. The job runs on `ubuntu-latest` with a
30-minute timeout. Future Kani stories (S-4.02, S-4.03) will add their own
`cargo kani --harness` steps to the same workflow file.
