# Finding dedup / rollup

## Problem

Today's plaintext-credentials detector groups events by
`(CredKind, dst, dst_port)`, producing one Critical finding *per
destination*. On the 4SICS-GeekLounge-151022 capture this produced
**12 duplicate Telnet findings**, several FTP findings, and several
HTTP-Basic findings. The findings list becomes 21 items long mostly
because the same kind of issue is repeated per host.

That's noise. A reader scanning the report sees a wall of duplicate
Critical entries and the *actually distinct* findings (S7
engineering, Modbus engineering, internet egress) get lost in the
middle.

## Decision

Roll up by **kind only**. One finding per CredKind (Telnet, FTP,
HTTP-Basic, SNMPv1/v2c). Destinations move from "key" to "evidence."

```
[Critical] Telnet observed (cleartext by definition)
Telnet traffic seen to 12 distinct host(s). Credentials traversing
these flows should be considered exposed.

Evidence (12 hosts):
  192.168.x.5:23 (1,247 packets)
  192.168.x.10:23 (892 packets)
  192.168.x.12:23 (456 packets)
  ... (9 more)

Recommendation: Migrate the device(s) to SSH if supported, ...
```

The "X packet(s) across Y host(s)" summary lets the reader see scope
at a glance. Evidence lists the destinations sorted by packet count
(noisiest first) up to the existing evidence cap.

## What stays the same

- Severity per CredKind (all Critical for now).
- Recommendation text per CredKind.
- The four credential kinds we detect.

## What changes

- `findings/plaintext_creds.rs::detect` rewrites the grouping logic.
  One `Finding` per CredKind that has at least one event.
- Output evidence is destination-shaped: `dst:port (N packet(s))`,
  sorted by packet count desc, capped at 15 samples.
- Snapshot for `findings_json` regenerates (the JSON shape changes:
  fewer findings, richer evidence per finding).
- Snapshot for HTML / scrubbed markdown regenerates accordingly.

## Out of scope

- Same dedup for the engineering-commands findings (Modbus / CIP /
  S7) — those already group by `(src, dst)` pair, which is the right
  granularity for "who is doing what to whom" and shouldn't roll up
  to one bucket. If we ever need it for very busy captures we can
  revisit.
- Same dedup for internet-egress / unexpected-protocols. Both
  already produce one finding total with the destinations in
  evidence — they're already deduplicated by design.

## Touched files

- `src/findings/plaintext_creds.rs` — rewrite `detect()`.
- `tests/snapshots/snapshot__findings_json.snap` — regenerate.
- `tests/snapshots/snapshot__report_html.snap` — regenerate.
- `tests/snapshots/snapshot__scrubbed_markdown.snap` — regenerate.

No new tests required; the existing snapshot suite catches the
output shape change. New unit test added for the rollup property
(N events across M hosts → 1 finding listing M destinations).
