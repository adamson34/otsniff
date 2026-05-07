# ADR-0001: Pure Rust, no Zeek dependency

## Status
Accepted

## Context
Two viable architectures for the v0.1 PCAP triage tool:

1. **Wrap Zeek + ICSNPP** — invoke Zeek as a subprocess, post-process its
   structured logs in Rust. Inherits the maturity of CISA/INL's ICSNPP
   parsers (Modbus, DNP3, EtherNet/IP, S7Comm, BACnet, IEC-104, OPC-UA, etc.).

2. **Pure Rust** — read PCAPs natively with `pcap-parser` + `etherparse`,
   write minimal protocol parsers in Rust for the protocols v0.1 covers.

## Decision
Pure Rust. No Zeek dependency.

## Rationale
- The product promise is "drop the binary on a consultant's laptop and run
  it" — a single static binary. Zeek requires a system install (or Docker),
  which collapses that UX into a Malcolm-lite deployment.
- v0.1 only needs Modbus/TCP and EtherNet/IP. Both are well-specified and
  the findings layer only needs function-code-level recognition, not full
  protocol decoding. The cost of writing those parsers ourselves is small
  (a weekend) compared to the perpetual cost of a Zeek install dependency.
- ICSNPP's broad protocol coverage matters when we expand to DNP3/S7Comm
  in v0.2+, but pulling in the dependency now would constrain the
  distribution model for protocols we don't yet support.

## Consequences
- Must hand-write each protocol parser (~200 lines per protocol). Each
  protocol becomes its own deliberate scope decision rather than a free
  add-on.
- Can ship a single ~5MB static binary via cross-compilation (Linux x86_64,
  Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64).
- If we ever need *full* protocol fidelity (e.g., to extract register
  values, not just function codes), revisit this decision.

## Alternatives considered
- **Zeek wrapper in Python** — rejected: same Zeek dep cost, plus loses
  the single-binary distribution.
- **libpcap binding** — `pcap-parser` is pure-Rust and works on offline
  PCAPs without libpcap, which avoids one more system dependency.
