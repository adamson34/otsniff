---
story_id: S-2.01
cycle: v0.4.0-feature
recorded: 2026-05-14T00:00
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-2.01 Port-to-label Table Lockdown

Regression-lockdown story. Adds 4 unit tests in
`src/findings/unexpected_protocols.rs` that pin the 11-row
port-to-label table (BC-AUDIT-009). No implementation change.

The lockdown value is prospective: any future refactor that drops a
table row, renames a label, narrows a port range, or changes
protocol-number handling will cause at least one test to fail in CI
before the change ships.

## AC-001 — Positive assertions per row

Evidence: ![tests](AC-001-002-lockdown-tests.gif) +
[test-output.txt](AC-001-002-test-output.txt)

`unexpected_label_lookups_match_canonical_table` asserts the canonical
mapping for every row: smtp / bittorrent / rtmp / apns / gcm / stun /
sip / irc / openvpn / teamviewer / anydesk.

## AC-002 — Negative sentinels

- `unexpected_label_returns_none_for_unmapped_ports` — telnet (23),
  http (80), https (443), ssh (22), modbus (502), 0, 65535
- `unexpected_label_returns_none_for_non_tcp_udp` — ICMP, GRE, ESP, SCTP
- `unexpected_label_distinct_label_set_is_exactly_eleven` — set-cardinality
  invariant (sweeps the table, asserts exactly 11 distinct labels)
