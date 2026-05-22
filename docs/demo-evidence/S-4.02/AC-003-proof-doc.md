# AC-003: Proof Documentation — docs/proofs/leak-detector-regex.md

Source: `head -60 docs/proofs/leak-detector-regex.md`

```markdown
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

## Proof Strategy

The `regex` crate internally uses heap-allocated state machines that interact
poorly with fully symbolic Kani inputs.  Following the guidance from S-4.02
("better narrow + honest than broad + speculative"), each harness fixes the
*structure* of the address string while making its *content* fully symbolic
within the relevant alphabet (decimal digits for IPv4, hex nibbles for MAC).

This is narrower than a pure symbolic-string proof but still machine-checked:
Kani exhaustively explores every value assignment for the symbolic digit/nibble
variables, proving the regex fires for every input in the constrained domain.

---

## Harnesses

### `leak_regex_ipv4`

**Location:** `src/ai/leak_detector.rs`, `kani_proofs::leak_regex_ipv4`

**Property:** for every dotted-quad string `D.D.D.D` where each `D` is a
single decimal digit (0–9), `scan(s)` returns
`Some(Leak { kind: LeakKind::Ipv4, .. })`.

**Symbolic domain:** four independent `u8` values, each constrained to 0–9 via
`kani::assume(x <= 9)`.  The dotted structure is fixed; only the four digit
values are symbolic.  This covers 10^4 = 10 000 distinct address strings.

**Adversarial shapes covered:**
- Address at string start (word boundary at byte 0)
- Address at string end (word boundary at end-of-string)
- All-zeros: `0.0.0.0`
- All-nines: `9.9.9.9`

**Intentional narrowing:** each octet is a *single* decimal digit.  Multi-digit
octets (e.g. `192.168.1.5`) are exercised by the unit test
`flags_ipv4_in_otherwise_clean_text` and by `cargo fuzz`.  The harness proves
the regex fires for every single-digit-per-octet address value.
```
