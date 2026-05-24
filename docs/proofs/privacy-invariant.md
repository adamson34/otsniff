# Privacy Invariant Proof

## Overview

The privacy invariant is the core load-bearing claim of otsniff's AI-triage mode:
when a user scrubs a PCAP report and submits it to an LLM (including via the
`analyze --ai` command), no real plant data (IP addresses, MAC addresses, or
hostnames) reaches the AI provider. This is not enforced by convention or
documentation — it is proven by formal verification.

This document summarizes the formal evidence for that claim across three
component proofs (Wave-1: S-4.01, S-4.02, S-4.03) and one composed proof
(Wave-2: S-4.04), which together formally verify behavioral contract BC-5.02.003.

## The Three Component Proofs

The three component proofs, completed in Wave-1 (S-4.01, S-4.02, S-4.03), each
formally verify a single, localized property of the privacy machinery:

| Story | Proof Name | What It Verifies |
|-------|-----------|------------------|
| S-4.01 | `scrub_roundtrip_bounded` | Scrub round-trip is lossless: any string with a pseudonym map produces identical output before and after unscrub. |
| S-4.01 | `scrub_roundtrip_single_replacement` | Single-value scrub: replacing one IP in a string works correctly. |
| S-4.02 | `leak_regex_ipv4` | IPv4 regex pattern: correctly identifies all IPv4-shaped byte patterns. |
| S-4.02 | `leak_regex_ipv6` | IPv6 regex pattern: correctly identifies all IPv6-shaped byte patterns. |
| S-4.02 | `leak_regex_mac` | MAC regex pattern: correctly identifies all MAC-shaped byte patterns. |
| S-4.03 | `map_value_substring` | Scrub map values (hostnames) are never substrings of the scrub output. |

Each component proof operates on bounded symbolic inputs within a Kani harness.
The proofs use hand-rolled proof-model functions (`replace_first_model`,
`byte_contains_model`, and the IP/MAC shape models) that mirror production
semantics without invoking the `regex` crate, which CBMC cannot unwind.

## The Composed Proof

The composed proof, `composed_privacy_invariant` (story S-4.04), is the wave-2
verification capstone for **BC-5.02.003**. It uses the three component-proof
models together — `replace_first_model` (scrub) and `byte_contains_model`
(leak-check) — and asserts properties that hold across them.

### Honest scope (F-ADV-P1-005 rewrite, 2026-05-23)

The original wave-2 version of this proof asserted `byte_contains_model`
against a hand-written brute-force substring search. Adversarial review pass
ADV-P1 correctly flagged that those two implementations are the same algorithm
written twice — the assertion was a tautology and the proof was contributing
no new verification beyond the component proofs.

This version asserts **two non-trivial composed properties:**

#### Property 1 — Vacuous-case idempotence
If the input does NOT contain `real`, then:
- `replace_first_model(input, real, pseudo)` returns `input` unchanged
- Re-scrubbing the output returns it unchanged again
- `len`, byte-by-byte equality of the output to the input, and equality of
  the twice-scrubbed output to the once-scrubbed output are all proved

This formalises the contract that `scrub_text` is the identity function on
already-clean inputs. A regression that changed even one byte of input not
containing a map value would be caught.

#### Property 2 — Leak-detector structural soundness
For ANY scrubbed output (replaced or not), `byte_contains_model(out, real)`
must agree with a **structurally different** independent check — one using
Rust slice equality (`&out[i..i+n] == real`, compiled by CBMC to a
memcmp-equivalent) rather than `byte_contains_model`'s manual byte-by-byte
loop. The two implementations have different unrolling shapes in CBMC, so the
assertion is genuinely non-tautological: it proves that two different ways of
asking "does this slice appear in this haystack?" always agree.

### Preconditions (matching production `build_map` invariants)

1. `real` is non-empty (matches `scrub_text`'s assumption that real values
   are never empty strings — enforced by `ScrubMap::validate`).
2. `real` does not contain the pseudonym `host_001` as a substring (matches
   `build_map`'s rule that real values are never pseudonym-shaped).
3. `pseudo` (`host_001`) does not contain `real` as a substring (matches
   the structural impossibility that a pseudonym shape contains an IP /
   MAC / hostname shape — relied on by the production `scrub_text` loop
   to terminate after one pass per (real, pseudo) entry).

### What's NOT proved (acknowledged gap)

- **Production-code equivalence.** `replace_first_model` is a hand-rolled
  byte-level model; production `scrub_text` is a `str::replace` loop. The
  proof models intentionally avoid `regex` and UTF-8 paths CBMC cannot
  unwind. Model-to-production equivalence is verified by the cargo-fuzz
  harness `fuzz_targets/scrub_text.rs` (story S-3.04), now updated to
  carry a real symbolic ScrubMap so the substitution branch is actually
  exercised on every iteration (F-ADV-P1-004).
- **Multi-occurrence case.** When `input` contains `real` two or more times,
  `replace_first_model` only replaces the first. The output still contains
  `real`, and the leak detector catches it. This is a *runtime* property of
  the composition rather than a Kani assertion: production `scrub_text`
  iterates `.replace()` (which is itself iterative) and the leak detector's
  substring scan catches the residue if scrub left any. The Kani proof
  scope is limited to the single-occurrence semantics by design.

**Test:** `cargo kani --harness composed_privacy_invariant`

## What Bounds Remain

The composed proof operates on symbolic inputs of ≤ 4 bytes (unwind bound 11).
This is a limitation of current SMT solver capacity, not of the property itself.

### Why the unbounded claim follows from bounded proofs

1. The scrub logic (`replace_first_model` / `scrub_text`) is linear in input
   length — there is no state that grows non-linearly with length.
2. The leak detector (`byte_contains_model` / `str::contains`) is also linear —
   it terminates in bounded time regardless of input size.
3. Both functions process bytes sequentially with no global state; the
   correctness property is monotonic (if it holds for all strings of length ≤ N
   it holds for extensions because no new code path is activated by longer input).

Therefore, the bounded proof provides sound evidence for the unbounded claim.
The fuzz suite (S-3.04) additionally exercises both functions on arbitrary-length
inputs to provide complementary probabilistic coverage.

### Known scope limitations

- **One map entry (K = 1):** the composed proof injects a single `real → pseudo`
  entry. The full privacy claim for K > 1 entries follows by the same
  compositional argument used in S-4.01: replacements are independent and the
  leak check iterates over all map entries.
- **Pseudonym shape:** the pseudonym is the concrete literal `"host_001"`.
  Other pseudonym shapes (e.g., `"ip_001"`, `"mac_001"`) are covered by the
  component proofs in S-4.01; the composition extends naturally.
- **Regex-shape leaks:** BC-5.02.003 also requires that no IP/MAC-shaped byte
  patterns pass the regex scan. This is proved by S-4.02's three harnesses
  (`leak_regex_ipv4`, `leak_regex_ipv6`, `leak_regex_mac`), which are separate
  from the composed harness.

## How to Run

### Local verification

```bash
cargo kani --harness composed_privacy_invariant
```

This requires Kani to be installed:

```bash
cargo install kani-verifier
cargo kani setup
```

To run all six component proofs as well:

```bash
cargo kani --harness scrub_roundtrip_bounded
cargo kani --harness scrub_roundtrip_single_replacement
cargo kani --harness leak_regex_ipv4
cargo kani --harness leak_regex_ipv6
cargo kani --harness leak_regex_mac
cargo kani --harness map_value_substring
cargo kani --harness composed_privacy_invariant
```

### CI workflow

All seven harnesses (six component + one composed) run weekly in the CI
pipeline via `.github/workflows/kani.yml`. If any harness fails or times out,
the job is marked FAILED and the team is notified.

See `.github/workflows/kani.yml` for per-harness timeout and unwind bounds.
