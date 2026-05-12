# ADR-0009: Drop ephemeral src_port from flow key (logical-flow grouping)

## Status
Accepted (v0.2)

## Context
TCP and UDP sessions have two ports: destination (stable, identifies the
service) and source (ephemeral, chosen by the OS from the ~30,000-slot
ephemeral range and recycled). For long-lived captures and especially
for SPAN-mirrored traffic, each new TCP connection from the same client
to the same server gets a new source port. A 24-hour SPAN of a Modbus
master polling 10 PLCs would produce thousands of distinct
`(src_ip, src_port, dst_ip, dst_port)` 4-tuples that all represent the
same logical conversation.

An analyst looking at the asset inventory does not care that `host_001`
opened TCP source ports 49152 through 54000 to `host_003:502` over the
course of the day. They care that `host_001` is a Modbus master talking
to `host_003` on port 502 — one logical flow.

Two flow-key shapes were considered:

1. **Full 5-tuple:** `(src_ip, src_port, dst_ip, dst_port, proto)` —
   one record per TCP connection. Forensically complete but produces
   high-cardinality output that is unreadable in an inventory report.

2. **Logical-flow 4-tuple:** `(src_ip, dst_ip, dst_port, proto)` —
   one record per logical conversation. src_port is dropped; a
   `connections: u32` field counts the distinct src_ports observed
   for that logical flow.

## Decision
`Observations::flows` is keyed by `(src: IpAddr, dst: IpAddr,
dst_port: u16, proto: u8)`. Source port is not part of the key.

Each `Flow` record in the map carries a `connections: u32` counter
that is incremented whenever a new src_port is seen for a given logical
key. This preserves the signal ("this master opened 847 connections
today — unusual") without generating 847 rows in the inventory.

## Rationale

- **Analyst-facing cardinality.** The inventory table in the report is
  meant to be scanned in a few minutes. A table with thousands of rows
  for a single-day SPAN is not scannable. Logical flow grouping keeps the
  table bounded by `(hosts × services)`, not `(hosts × connections)`.
- **Finding correctness.** Several detectors (`unexpected_protocols`,
  `engineering_commands`) need to ask "did host A ever talk to host B
  on this port?" — a logical-flow question, not a connection-count question.
  The 4-tuple key answers that correctly regardless of how many TCP
  handshakes were observed.
- **4SICS validation.** The public 4SICS-22 PCAP was the first real
  test. With a full 5-tuple key, the flow table had several hundred rows;
  with the 4-tuple key it collapsed to a compact, readable set. The
  `connections` counter correctly captured the repetition.

## What is lost

- **Per-connection source-port trace.** If the source port matters for
  forensics (e.g., correlating with a firewall log entry), the analyst
  must go back to the raw PCAP. `otsniff` is a triage tool, not a
  forensics tool; this trade-off is acceptable.
- **Connection-timeline reconstruction.** Knowing when each TCP
  connection started and ended is not possible from the logical-flow
  record. Again: triage, not forensics.

## Alternatives considered

- **Store both:** emit a logical-flow table for inventory and a
  connection table for a "verbose" mode. Deferred — adds rendering
  complexity and no known user demand.
- **Configurable key:** let the user pass `--full-flows` to switch to
  5-tuple grouping. Deferred for the same reason; the default should be
  the analyst-friendly view.

## Implementation note

`src/observe.rs` defines:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
}
```

`Observations::flows: BTreeMap<FlowKey, Flow>` uses `BTreeMap` for
deterministic iteration order in reports and snapshot tests.

## Consequences

- Flow table size is `O(hosts × services)`, not `O(connections)`.
  Reports remain readable on multi-day SPAN captures.
- The `connections` counter is reported as a column in the flows section
  of the HTML and markdown reports.
- Any future feature that needs per-connection detail (e.g., a
  `--flows-verbose` mode) can derive it from the raw PCAP alongside the
  logical-flow summary.
