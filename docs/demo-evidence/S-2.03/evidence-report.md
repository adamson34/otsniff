---
story_id: S-2.03
cycle: v0.4.0-feature
recorded: 2026-05-12T00:00
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-2.03 OUI Table Refresh

Otsniff's vendor-inference table grew from 43 hand-curated entries
to 9,243 entries sourced from the IEEE MA-L OUI registry (filtered
to industrial + common-IT vendor patterns). Lookup is now O(log N)
via `binary_search_by_key`.

## AC-001 / AC-002 — Table size + sort order

Evidence: ![tests](AC-001-002-oui-tests.gif)
Growth: [table-growth.txt](AC-001-table-growth.txt)

All five `oui::tests` pass: table_has_at_least_3000_entries,
table_is_sorted_by_prefix, table_resolves_named_industrial_vendors,
table_resolves_common_it_vendors, lookup_uses_binary_search.

## AC-003 — Named vendor resolution

Evidence: [vendor-samples.txt](AC-003-vendor-samples.txt)

Sample of resolved vendors: Cisco, Dell, HP, VMware, Microsoft,
Intel, Siemens, Rockwell/Allen-Bradley, Beckhoff, Moxa, Phoenix Contact,
Yokogawa, Mitsubishi, Omron, ABB, Schneider Electric, Honeywell,
Emerson — all present.

## AC-004 — No regression

Full test suite green: 94 lib + 15 cli_smoke + 23 snapshot = 132
tests, 0 failed. Clippy + fmt clean. POL-12 lint clean.

Binary size delta: +200 KB (release build, within AC-002 bound).
