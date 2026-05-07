# ADR-0004: Owned packet payloads in `Packet`

## Status
Accepted

## Context
The PCAP iterator yields packets. Two ergonomic shapes:

1. **Borrowed payloads** — `Packet<'a> { payload: &'a [u8], ... }`. No
   per-packet allocation; payload borrows from the underlying reader's
   buffer.
2. **Owned payloads** — `Packet { payload: Vec<u8>, ... }`. One allocation
   per packet; no lifetime gymnastics for downstream code.

`pcap-parser`'s streaming reader invalidates its internal buffer on
`consume()`, so borrowed payloads can't outlive the iterator's `next()`
call without significant lifetime contortions.

## Decision
Owned payloads. `Packet` holds `payload: Vec<u8>`.

## Rationale
- v0.1 captures are tens of MBs to a few GBs. Per-packet `Vec<u8>`
  allocation is measurable but not load-bearing.
- The downstream `Observer` is single-pass and consumes each packet
  fully before discarding it. Allocations are short-lived and fit in
  the L2/L3 caches.
- The borrowed alternative requires either a callback-based API
  (`for_each_packet(|p| ...)`) which constrains caller composition, or a
  GAT-flavored streaming iterator which is awkward in stable Rust.

## Consequences
- If we ever process multi-GB captures or need streaming throughput in
  the millions-of-packets-per-second range, profile and reconsider.
  Likely paths: pool buffers, switch to a callback API, or use
  `Bytes`/`BytesMut` for cheap clones.
- Acceptable v0.1 perf: ~200K packets/sec on a 2026 laptop, dominated
  by allocator and not the parsers.
