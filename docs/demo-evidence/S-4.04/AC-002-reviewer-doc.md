# AC-002: Reviewer Documentation — Privacy Invariant Proof Summary

## Document Existence

The reviewer-ready summary document exists at `docs/proofs/privacy-invariant.md` (149 lines, 5,847 words).

## Section Headers

The document is structured into five major H2 sections:

```
## Overview
## The Three Component Proofs
## The Composed Proof
## What Bounds Remain
## How to Run
```

## Section Summaries

### Overview
Introduces the privacy invariant as the core load-bearing claim: when scrubbing a PCAP and submitting to an LLM (via `analyze --ai`), no real plant data (IPs, MACs, hostnames) reaches the AI provider. This is proven by formal verification across Wave-1 (three component proofs: S-4.01, S-4.02, S-4.03) and Wave-2 (composed proof: S-4.04), collectively verifying behavioral contract **BC-5.02.003**.

### The Three Component Proofs
Documents the three localized component proofs from Wave-1, each verifying a single property:
- **S-4.01** `scrub_roundtrip_bounded` — Scrub round-trip is lossless
- **S-4.01** `scrub_roundtrip_single_replacement` — Single-value scrub works correctly
- **S-4.02** `leak_regex_ipv4` — IPv4 regex correctly identifies patterns
- **S-4.02** `leak_regex_ipv6` — IPv6 regex correctly identifies patterns
- **S-4.02** `leak_regex_mac` — MAC regex correctly identifies patterns
- **S-4.03** `map_value_substring` — Scrub map values never leak as substrings

### The Composed Proof
Explains how the composed proof (S-4.04) proves the end-to-end behavioral contract **BC-5.02.003**: for any bounded input containing real plant data, after scrubbing and leak-checking, either all real values are absent OR the leak detector returns an error. Describes the three proof-model helpers, the harness structure, and why the full privacy claim follows from the composition.

### What Bounds Remain
Discusses the bounded nature of the proof (≤ 4 bytes input, unwind 13) and why the unbounded claim follows: both scrub and leak-detector functions are linear in input length with no state growth, so the monotonic correctness property extends to arbitrary-length inputs. Notes that the fuzz suite (S-3.04) provides complementary probabilistic coverage for unbounded inputs. Lists known scope limitations (single map entry K=1, concrete pseudonym "host_001", regex-shape leaks covered separately by S-4.02).

### How to Run
Provides commands for local verification and CI integration:
- Local: `cargo kani --harness composed_privacy_invariant`
- All seven harnesses: individual cargo commands for each proof
- CI workflow: `.github/workflows/kani.yml` runs all seven harnesses weekly and on every push to main/develop

## Cross-Reference to Behavioral Contract

The document explicitly references **BC-5.02.003** six times, making the traceability to the behavioral contract clear:

> "...collectively formally verify behavioral contract **BC-5.02.003**."

> "...proves the end-to-end behavioral contract **BC-5.02.003**: *for any bounded input string containing real plant data, after scrubbing and then leak-checking, either all real values are absent from the output OR the leak detector returns an error.*"

This ensures reviewers understand which acceptance criterion and behavioral contract the formal proof addresses.

## Document Quality Metrics

- **Lines:** 149
- **Words:** 5,847
- **Sections:** 5 H2 headers, multiple H3 subsections (17 total)
- **Proof count documented:** 7 harnesses (6 component + 1 composed)
- **Scope limitations explicitly listed:** 3 (K=1, pseudonym shape, regex-shape leaks)
- **Code examples:** 2 (local verification, CI workflow)
