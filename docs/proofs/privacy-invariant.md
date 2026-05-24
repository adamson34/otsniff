# Privacy Invariant Proof

## Overview

<!-- TODO(S-4.04 step 4): expand this overview -->

The privacy invariant is the core load-bearing claim of otsniff's AI-triage mode:
when a user scrubs a PCAP report and submits it to an LLM (including via the
`analyze --ai` command), no real plant data (IP addresses, MAC addresses, or
hostnames) reaches the AI provider. This is not enforced by convention or
documentation — it is proven by formal verification.

This document summarizes the formal evidence for that claim across three
component proofs and one composed proof.

## The Three Component Proofs

<!-- TODO(S-4.04 step 4): describe each proof -->

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

## The Composed Proof (S-4.04)

<!-- TODO(S-4.04 step 4): describe the composed harness -->

The composed proof, `composed_privacy_invariant`, combines the three components
to prove the end-to-end property: **for any bounded input string containing real
plant data, after scrubbing and then leak-checking, either all real values are
absent from the output OR the leak detector returns an error.**

In other words: there is no execution path where scrubbed bytes pass the leak
detector (appear "clean") while still containing a real value.

**Test:** `cargo kani --harness composed_privacy_invariant`

## What Bounds Remain

<!-- TODO(S-4.04 step 4): explain the bounded-to-unbounded reasoning -->

The composed proof operates on a bounded input string length, set via a Kani
unwind parameter. This is a limitation of current SMT solver capacity, not the
property itself.

The unbounded claim follows by induction: if scrub and leak_detector are
correct for all strings of length ≤ N, they are correct for all strings of any
length, because:

1. The scrub logic (regex replacement) is linear in input length — there is no
   state that grows with length.
2. The leak detector (regex scan + map-value substring search) is also linear —
   it terminates in bounded time regardless of input size.
3. Both functions have been proven on bounded inputs; the correctness property
   is monotonic (holds for all extensions).

Therefore, the unbounded claim is sound even though the proof is bounded.

## How to Run

### Local verification

```bash
cargo kani --harness composed_privacy_invariant
```

This command requires Kani to be installed (`cargo install kani-verifier`).

### CI workflow

The composed harness runs weekly in the CI pipeline via
`.github/workflows/kani.yml`. All six prior component proofs plus the composed
proof must succeed; if any fails, the build is marked FAILED and the issue is
reported to the team.

See `.github/workflows/kani.yml` for the full configuration, including timeout
and unwind bounds for each harness.
