# ADR-0010: Roll up plaintext-cred findings by kind

## Status
Accepted (v0.2, shipped as P0-1)

## Context
The initial findings layer emitted one finding per (host, protocol):
one "Telnet observed" finding for `host_001`, another for `host_002`,
another for `host_003`. A network with 12 Telnet-capable hosts produced
12 separate finding cards in the report — each with severity `High`,
each with its own evidence section pointing to one destination.

The 4SICS-22 public test PCAP triggered this immediately: 12 identical
"Telnet observed" cards appeared at the top of the report, burying all
other findings and making the report noisy rather than actionable. An
analyst looking at the report needs to understand "plaintext credentials
are in use on this network" — the single insight — not scroll through 12
restatements of the same problem.

Two approaches for handling multi-host plaintext cred findings:

1. **Per-destination findings** — one finding per (host, proto). Every
   destination is a separate top-level card. High cardinality when many
   hosts share the same weakness.

2. **Per-kind rollup** — one finding per credential kind (`creds.telnet`,
   `creds.ftp`, `creds.http_basic`, `creds.snmp`). All destinations are
   listed as evidence rows within that single finding.

## Decision
`findings::plaintext_creds` emits **one finding per credential kind**.
All destinations where that credential type was observed appear as
evidence rows (up to the 5-sample evidence cap). The finding severity is
derived from the worst-case instance (all plaintext cred kinds are `High`).

The same rollup pattern is applied to any finding class where the
finding body would be identical across destinations:

- `ics.*` engineering-command findings: one finding per ICS command
  class, not one per host that issued the command.
- `boundary.*` internet-egress findings: one finding, all source hosts
  as evidence.
- `compat.*` unexpected-protocol findings: one finding per protocol,
  not one per host using it.

## Rationale

- **Signal-to-noise.** An analyst scanning the finding cards should see
  the distinct security issues on the network, not a restatement of each
  issue N times. Rolling up by kind reduces the card count to the number
  of distinct issues, not the number of affected hosts.
- **Evidence cap.** Each finding carries up to 5 evidence samples. In a
  per-destination world, every card has 1 sample (the one host). In a
  rolled-up world, 5 representative destinations are shown. Both are
  readable, but the rollup gives more context per card.
- **Ranking stability.** Findings are sorted by severity then by finding
  ID. When there are 12 identical `High` Telnet cards, the sort is
  deterministic but arbitrary — no one card is "first" for a meaningful
  reason. With rollup, one `creds.telnet` card appears once in its
  correct severity band.
- **Report length.** Keeping the report concise enough to hand to a
  non-technical stakeholder matters for the target audience. A 12-card
  repeated section defeats that goal.

## Evidence cap

Each finding stores up to 5 evidence rows (`const MAX_EVIDENCE: usize = 5`).
When there are more than 5 affected destinations, the evidence list is
truncated and the finding description notes the actual count
("12 destinations total; 5 shown"). This cap prevents extremely large
evidence blocks in networks with hundreds of hosts, while still providing
enough representative examples for an analyst to verify the finding.

## Alternatives considered

- **Group but expand on click** — requires dynamic HTML, which conflicts
  with the self-contained static-HTML design goal. All interactivity would
  require JavaScript and would break the "save and share" use case.
- **Show all evidence, paginated** — same problem: requires dynamic
  rendering or a very long static table. Not pursued.
- **Per-destination as the default, rollup as a flag** — rejected because
  per-destination output is almost never the analyst-useful default, and
  having a flag for it adds CLI complexity for little gain.

## Consequences

- Reports from PCAPs with many hosts sharing a weakness remain concise
  (bounded by number of finding kinds, not number of hosts).
- The evidence section of each finding is the canonical place to see which
  hosts are affected; the card title summarises the issue.
- Adding a new credential protocol (e.g., `creds.snmpv1`) is additive:
  add a new kind constant, add detection logic, the rollup pattern handles
  the rest.
- The per-kind grouping is implemented with `BTreeMap<CredKind, Vec<Evidence>>`
  inside the detector function, ensuring deterministic output order across runs.
