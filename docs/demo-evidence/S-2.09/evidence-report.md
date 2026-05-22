---
story_id: S-2.09
cycle: v0.4.0-feature
recorded: 2026-05-14T00:00
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-2.09 boundary.ntp_external Detector

S-2.09 introduces the `boundary.ntp_external` detector: fires when an OT-zone
host sends NTP queries (UDP/123) to a destination outside every configured
`--ot-subnet`. The detector is registered in `src/findings/ntp_external.rs` and
wired into `src/findings/mod.rs`.

Behavioral contracts under test:
- **BC-1.05.003** — a flow with `dst_port = 123`, src in OT, dst not in OT produces
  exactly one `boundary.ntp_external` finding.
- **BC-3.05.004** — multicast destination `224.0.1.1` (IANA NTP multicast, RFC 5905)
  is treated as outside the OT zone and therefore triggers the finding.

---

## AC-001 — Cross-zone NTP detection

Evidence: ![ac-001](ac-001-ntp-detection.gif)

**Artifact:** `docs/demo-evidence/S-2.09/ac-001-ntp-detection.tape`

The recording runs all four `ntp_external` snapshot tests via
`cargo test --test snapshot ntp_external -- --nocapture`. All four tests pass
(`test result: ok. 4 passed`), covering the positive case (cross-zone flow fires
the finding), two negative cases (non-OT source and intra-OT traffic both
correctly produce no finding), and the EC-003 multicast case. The second command
pipes `otsniff rules --format md` through `grep -A4 'boundary.ntp_external'`
so the viewer can read the rule's trigger text and severity directly from the
compiled binary.

What to look for in the recording:
- The test runner prints four `ok` lines and a final `test result: ok. 4 passed`.
- The rules output shows the `## boundary.ntp_external` section header,
  the `**OT host syncing time to public NTP**` title, and `**Severity:** medium`.

---

## EC-003 — Multicast destination 224.0.1.1 flagged

Evidence: ![ec-003](ec-003-multicast.gif)

**Artifact:** `docs/demo-evidence/S-2.09/ec-003-multicast.tape`

The recording runs the focused test
`cargo test --test snapshot ntp_external_flags_multicast_destination -- --nocapture`.
This test constructs a flow where an OT host (`192.168.1.10`) sends UDP/123
packets to `224.0.1.1` — the IANA-assigned NTP multicast group address
(RFC 2030 / RFC 5905). Because `224.0.1.1` is not inside any configured OT
subnet, the detector must fire exactly once.

What to look for in the recording:
- The test name `ntp_external_flags_multicast_destination` appears in the runner
  output followed by `ok`.
- The final line reads `test result: ok. 1 passed`.

---

## Coverage Map

| Criterion | Test(s) | Recording |
|-----------|---------|-----------|
| AC-001 (BC-1.05.003) — cross-zone NTP fires | `ntp_external_fires_on_cross_zone_ntp_flow` | `ac-001-ntp-detection.gif` |
| AC-001 negative — non-OT source does not fire | `ntp_external_does_not_fire_for_non_ot_source` | `ac-001-ntp-detection.gif` |
| AC-001 negative — intra-OT does not fire | `ntp_external_does_not_fire_for_intra_ot_traffic` | `ac-001-ntp-detection.gif` |
| EC-003 (BC-3.05.004) — multicast 224.0.1.1 fires | `ntp_external_flags_multicast_destination` | `ec-003-multicast.gif` |
| Rule catalog visible via `rules --format md` | `cargo run -- rules` output in recording | `ac-001-ntp-detection.gif` |
