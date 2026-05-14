---
story_id: S-1.03
cycle: v0.4.0-feature
recorded: 2026-05-14T00:00
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-1.03 Close ASR-003..007 PRD Findings (Code Half)

S-1.03 covers two code-level fixes that close open PRD findings:

- **AC-005** pins the `ot_or_default(&[])` contract: when no OT subnets are
  supplied, the function returns only IPv4 RFC 1918 prefixes (no IPv6 ULA
  range was added at this stage).
- **AC-006** removes the stale "password operations" wording from the
  `S7_METADATA` trigger description and replaces it with explicit function-code
  references (0x05, 0x1A-0x1C, 0x1D-0x1F, 0x28, 0x29).

## AC-005 — `ot_or_default(&[])` returns IPv4-only RFC 1918 default

Evidence: ![ac-005](ac-005-ot-default-ipv4-only.gif)

**Artifact:** `docs/demo-evidence/S-1.03/ac-005-ot-default-ipv4-only.tape`

The recording runs
`cargo test --lib cli::tests::ot_or_default_empty_input_returns_only_ipv4_rfc1918 -- --nocapture`
and shows `test result: ok. 1 passed`. It then pipes `analyze --help` through
`grep -A1 'ot-subnet'` so the viewer can confirm the `--ot-subnet` flag is
documented as the user-facing override. Look for: the green `ok` test result
on the first command, and `--ot-subnet <CIDR>` with the "CIDR ranges to treat
as OT zones" description on the second command.

## AC-006 — `S7_METADATA.trigger` no longer mentions "password"

Evidence: ![ac-006](ac-006-s7-trigger-no-password.gif)

**Artifact:** `docs/demo-evidence/S-1.03/ac-006-s7-trigger-no-password.tape`

The recording runs
`cargo test --lib findings::engineering_commands::tests::s7_metadata_trigger_does_not_mention_password -- --nocapture`
and shows `test result: ok. 1 passed`. It then pipes `rules --format md`
through `grep -A10` on the `ics.s7_engineering` section so the viewer can
read the updated trigger sentence. Look for: the green `ok` test result on
the first command, and the trigger text citing explicit function codes
`0x05 Write Var`, `0x1A-0x1C block download`, `0x1D-0x1F block upload`,
`0x28 PLC Control`, `0x29 PLC Stop` — with no mention of "password" anywhere.
