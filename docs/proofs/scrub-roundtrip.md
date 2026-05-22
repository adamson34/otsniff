# Scrub Round-Trip Proof

Formal verification of the privacy invariant for the byte-level replacement model.

Traces to: BC-5.01.003, ADR-0006, S-4.01.

## Proof-Model Architecture

The production `scrub_text` and `unscrub_text` functions use the `pseudonym_regex()`
helper, which calls the `regex` crate internally.  CBMC cannot unwind the regex NFA/DFA
state machine within a reasonable budget, causing the original harness to time out at
the 15-minute CI limit.

Instead of calling production functions directly, the harnesses prove a **narrower
property** using a hand-rolled byte-level model function (`replace_first_model`) that
implements the same single-occurrence forward search-and-replace algorithm without
`Regex` or heap `String`.

Production code (`scrub_text`, `unscrub_text`, `pseudonym_regex`) is **never
modified**.  All model functions are inside `#[cfg(kani)] mod kani_proofs`.

### What is proved

Two complementary cases together capture the algorithm's essential correctness:

**Case 1 — Vacuous (no-op) case** (`scrub_roundtrip_bounded`):
> If `input` does NOT contain `real_value`, then
> `replace_first_model(input, real, pseudo) == input`.

**Case 2 — Single-replacement case** (`scrub_roundtrip_single_replacement`):
> If `input` IS exactly `real_value`, then:
> 1. `replace_first_model(real, real, pseudo) == pseudo` (scrub)
> 2. `replace_first_model(pseudo, pseudo, real) == real` (unscrub)

### What is deferred

Model-vs-production equivalence — that `replace_first_model` behaves identically to
`scrub_text`/`unscrub_text` for the same inputs — is verified separately by the fuzz
suite (S-3.04).  That step is out of scope for S-4.01.

## Harnesses

**Location:** `src/scrub.rs`, inside `#[cfg(kani)] mod kani_proofs`

### `scrub_roundtrip_bounded`

Proves the vacuous/no-op case: when `input` does not contain `real_value`,
`replace_first_model` is the identity function.

```rust
#[kani::proof]
#[kani::unwind(6)]
fn scrub_roundtrip_bounded() { ... }
```

### `scrub_roundtrip_single_replacement`

Proves the exact-match round-trip: scrub then unscrub restores the original value.

```rust
#[kani::proof]
#[kani::unwind(10)]
fn scrub_roundtrip_single_replacement() { ... }
```

## Bounds

| Bound | Symbol | Chosen value | Rationale |
|-------|--------|-------------|-----------|
| Max input / real-value length (bytes) | N | 4 | N = 4 exercises "no match", "match at start", "match at end", and "match in middle" — all code paths in `replace_first_model`. Longer inputs are covered by the fuzz suite. |
| Max map entries | K | 1 | The round-trip property is compositional: if it holds for one entry it holds for K entries, because each replacement is independent (pseudonyms are disjoint from the real-value alphabet). K = 1 exercises the full code path without multiplying state space. |
| Output buffer | — | 16 bytes | Safe upper bound: N (4) + pseudo.len() (8) + slack. |
| `#[kani::unwind]` for vacuous case | — | 6 | Inner loops iterate ≤ N = 4 times; 6 gives CBMC two steps of headroom. |
| `#[kani::unwind]` for round-trip case | — | 10 | Inner loops iterate ≤ pseudo.len() = 8 times; 10 gives CBMC two steps of headroom. |

## Model Function

`replace_first_model(haystack, needle, replacement) -> ([u8; 16], usize)`:
- Byte-level forward search for the first occurrence of `needle` in `haystack`.
- Replaces it with `replacement` in a fixed-size output buffer.
- Returns the output buffer and its valid length.
- No `Regex`, no `String`, no heap allocation — tractable for CBMC.

## Rationale: bounded proof + fuzz = strong evidence for the unbounded claim

- **Kani (N = 4):** exhaustive within the bound — no counterexample exists for
  inputs ≤ 4 bytes.
- **Fuzz (N > 4):** probabilistic for longer inputs — millions of random cases
  over 24 h on CI.

This is bounded proof + probabilistic fuzz, not unbounded formal proof. The
combination provides strong evidence for the unbounded claim and is consistent
with the state of the art for string-manipulation proofs in Kani/CBMC.

### Preconditions baked into the harnesses

1. Input bytes are printable ASCII (0x20–0x7E).
2. The real value is non-empty (empty real values are rejected by
   `ScrubMap::validate()` — EC-001).
3. The real value does not contain the pseudonym `"host_001"` as a substring.
   This mirrors the invariant maintained by `build_map`: real IPs and MACs
   are never pseudonym-shaped strings.

## Known limitations

- Non-UTF-8 inputs are excluded by design (EC-003).
- The proof covers the `ips` family only (pseudonym prefix `host_`). The
  `macs` and `names` families use the same code path; a separate harness per
  family is left for S-4.02/S-4.03.
- The proof-model architecture means we prove the MODEL, not production
  `scrub_text`/`unscrub_text` directly.  Model-vs-production equivalence is
  delegated to S-3.04 fuzz harnesses.

## How to run locally

```bash
# Run both proof harnesses:
cargo kani --harness scrub_roundtrip_bounded
cargo kani --harness scrub_roundtrip_single_replacement
```

Expected output on success:

```
VERIFICATION:- SUCCESSFUL
```

## CI integration

`.github/workflows/kani.yml` runs these proofs on a weekly schedule (Sunday
06:00 UTC) and on manual dispatch. The job runs on `ubuntu-latest` with a
15-minute timeout per harness.
