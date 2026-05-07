# ADR-0005: Embedded OT-vendor OUI table

## Status
Accepted

## Context
The asset inventory benefits from showing the vendor name for each MAC
address (e.g., `00:30:A7 → Schweitzer Engineering`). The IEEE OUI registry
has ~30,000 entries.

Options:
1. Embed the full registry (~1MB compressed)
2. Embed a curated OT-relevant subset (~50 entries)
3. Look up from a file at runtime
4. Online lookup

## Decision
Embed a curated subset of OT-relevant vendors. Fall back to "Unknown" for
unrecognized OUIs. The user still sees the raw OUI bytes in the report
when the lookup misses.

## Rationale
- We want a single static binary (ADR-0001). Runtime file lookup adds a
  config story; online lookup adds a network dependency and privacy
  question (we'd be telling a server which MACs are on a plant network).
- The full registry is dominated by IT vendors that don't help an OT
  triage report. Embedding all 30K entries trades binary size for
  marginal value.
- A curated table reflects our domain knowledge: "Siemens, Rockwell,
  Schneider, ABB, Honeywell, GE, Mitsubishi, Omron, B&R, Phoenix Contact,
  WAGO, Beckhoff, SEL, Hirschmann, Moxa, ..." plus a handful of common
  IT vendors we'd see on plant LANs (Cisco, VMware, Raspberry Pi).

## Consequences
- New vendors are added by editing `src/oui.rs` — usually triggered by a
  real PCAP run that returned `vendor: null` for an interesting host
  (the SEL OUI was added this way during v0.1 development).
- If a user complains about a missing common vendor, that's a one-line
  PR. If they want exhaustive coverage, that's a v0.2+ story
  (likely: ship an embedded-via-include_bytes! trimmed registry built
  from the IEEE source).
