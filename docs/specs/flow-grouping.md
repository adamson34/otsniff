# Logical-flow grouping

## Problem

Today's `Observations.flows` is keyed by the full TCP/UDP 5-tuple
(`src_ip:src_port → dst_ip:dst_port/proto`). On real captures, this
produces an unreadable comms matrix:

- The DNP3-Malformed fuzz fixture: 198 packets, 1 logical conversation,
  but **198 distinct flows** because each test case opened a new TCP
  connection from a fresh ephemeral port.
- Any plant capture with HMI ↔ historian polling produces dozens of flows
  per host pair as Windows recycles ephemeral source ports.
- The "Top flows" table becomes meaningless — sorted by bytes, the top
  N rows are often slight variants of the same conversation.

## Decision

Drop `src_port` from the flow key. Aggregate by
`(src_ip, dst_ip, dst_port, proto)` — one entry per logical
"who-talks-to-whom-about-what." Track `unique_src_ports` separately on
`FlowObs` so we don't lose visibility into "how many distinct
connections."

## Output difference

Before:

```
| Source              | Destination          | Protocol | Packets | Bytes |
|---------------------|----------------------|----------|---------|-------|
| 192.168.0.1:53301   | 192.168.0.2:20000    | dnp3     | 1       | 22    |
| 192.168.0.1:53584   | 192.168.0.2:20000    | dnp3     | 1       | 18    |
| 192.168.0.1:53588   | 192.168.0.2:20000    | dnp3     | 1       | 25    |
... (195 more rows)
```

After:

```
| Source        | Destination         | Protocol | Conns | Packets | Bytes |
|---------------|---------------------|----------|-------|---------|-------|
| 192.168.0.1   | 192.168.0.2:20000   | dnp3     | 198   | 198     | 4.4K  |
```

The "Conns" column makes the connection burst itself a signal — useful
for spotting probe / fuzz / scan behavior.

## Implementation

- `FlowKey` drops `src_port`. The struct becomes
  `{ src, dst, dst_port, proto }`.
- `FlowObs` gains `unique_src_ports: HashSet<u16>` and a `connections()`
  helper returning `unique_src_ports.len()`.
- The Markdown and HTML "Top flows" tables gain a "Conns" column.
- Snapshot tests update to reflect the new shape.

## Scope

**In scope:**

- 5-tuple → 4-tuple flow aggregation
- Connection-count tracking
- Reports + JSON output reflect the new shape

**Not in scope:**

- "Active vs. ended connections" (we'd need TCP state tracking — out of
  v0.1's design scope)
- Per-connection timing / latency analysis
- Splitting bidirectional A↔B into a single logical flow (we keep
  forward and reverse as distinct logical flows for now; merging them
  is an option if the matrix is still noisy after this change)
