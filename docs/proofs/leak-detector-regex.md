# Leak Detector Regex Proof

Story: S-4.02  
Behavioral contract: BC-5.02.001  
Harnesses: `leak_regex_ipv4`, `leak_regex_ipv6`, `leak_regex_mac`  
Location: `src/ai/leak_detector.rs` — `#[cfg(kani)] mod kani_proofs`

---

## Purpose

Formally prove that the three regexes inside `src/ai/leak_detector.rs` —
`ipv4_regex()`, `ipv6_regex()`, and `mac_regex()` — match every
syntactically valid IPv4 address, IPv6 address (selected forms), and MAC
address that appears as a substring in a bounded input string.

This closes the gap between "we eyeballed the regex and it looks right"
and "we have a machine-checked proof that no IPv4/MAC/IPv6-shaped string
escapes detection."

---

## Harnesses

### `leak_regex_ipv4`

**TODO:** Document the harness.

- Property: for every string `s` of length ≤ N that contains a valid
  dotted-quad IPv4 address as a substring, `scan(s)` returns
  `Some(Leak { kind: LeakKind::Ipv4, .. })`.
- Adversarial shapes to cover: address embedded in log prefix, surrounded
  by punctuation, at string boundaries.
- Bounds rationale: TODO.

### `leak_regex_ipv6`

**TODO:** Document the harness.

- Property: for every string `s` of length ≤ N that contains a full
  8-group IPv6 address as a substring, `scan(s)` returns
  `Some(Leak { kind: LeakKind::Ipv6, .. })`.
- Coverage note: shorter bounds are acceptable for IPv6 due to the larger
  pattern size; document the specific bound and justify it.
- Bounds rationale: TODO.

### `leak_regex_mac`

**TODO:** Document the harness.

- Property: for every string `s` of length ≤ N that contains a
  colon-separated 6-octet MAC address (case-insensitive) as a substring,
  `scan(s)` returns `Some(Leak { kind: LeakKind::Mac, .. })`.
- Edge case: mixed-case (`aA:bB:cC:...`) — the detector normalizes;
  the proof must reflect that.
- Bounds rationale: TODO.

---

## Bounds Rationale

**TODO:** Fill in after implementing the harnesses.

Follow the same structure as `docs/proofs/scrub-roundtrip.md`:

- `N` — maximum input string length in bytes.
- `UNWIND` — loop-unwind bound required by CBMC.
- Relationship to the fuzz suite (cargo fuzz covers unbounded inputs).

---

## Run Instructions

```bash
# Run all three harnesses (requires cargo-kani):
cargo kani --harness leak_regex_ipv4
cargo kani --harness leak_regex_ipv6
cargo kani --harness leak_regex_mac

# CI: see .github/workflows/kani.yml (runs on Sunday 06:00 UTC or workflow_dispatch)
```

---

## Limitations

**TODO:** Document acknowledged limitations after implementation, e.g.:

- IPv6 zero-elision forms (`::1`, `fe80::`) may require a separate harness
  or explicit `kani::assume` constraints; document which forms are in scope.
- The regex does not validate that IPv4 octets are < 256 (conservative
  fail-closed design); the proof covers the shape, not numeric range validity.
