---
story_id: S-2.09
pr: 65
branch: feature/S-2.09-ntp-external
reviewer: vsdd-factory:pr-review-triage
cycle: 1
verdict: APPROVE
timestamp: 2026-05-14T00:00:00Z
---

# Review Findings — S-2.09 `boundary.ntp_external`

## Convergence Table

| Cycle | Findings | Blocking | Fixed | Remaining | Verdict |
|-------|----------|----------|-------|-----------|---------|
| 1     | 0        | 0        | 0     | 0         | APPROVE |

---

## Cycle 1 — Full Review

### Spec Fidelity (AC-001 / EC-003)

**PASS.** The detector fires exactly when specified:
- `src in OT && dst not in OT && dst_port == 123` → fires (AC-001 / BC-1.05.003)
- `224.0.1.1` (IANA NTP multicast) is not inside `10.10.0.0/16` → fires (EC-003 / BC-3.05.004)
- `src not in OT` → no finding (EC-001)
- `both src and dst in OT` → no finding (EC-002)

Evidence cap at 15 pairs confirmed (`sorted.iter().take(15)`). Rolls up by (src, dst) pair using
`BTreeMap<(IpAddr, IpAddr), u64>` — deterministic iteration, consistent with findings layer convention.

### Code Quality

**PASS.** The implementation mirrors `dns_resolver.rs` exactly in structure:
- Same `BTreeMap` accumulator pattern
- Same `sorted_by_key(Reverse)` for descending packet-count ordering
- Same `format_host_list` helper (identical implementation, private to module)
- Same `distinct_clients` BTreeSet for the summary count
- Same early-return on empty accumulator
- No unsafe code, no unwraps, no panics, no new dependencies

One observation (not a finding): `format_host_list` is duplicated verbatim between
`dns_resolver.rs` and `ntp_external.rs`. The sibling pattern has always had this duplication
and there is no shared utilities module for it. This is consistent with the codebase's
convention (ADR-0002 style: each finding module is self-contained). Not a blocking issue.

### Test Quality

**PASS.** Four snapshot tests in `tests/snapshot.rs`:
1. `ntp_external_fires_on_cross_zone_ntp_flow` — positive case, asserts `len == 1`, severity == Medium, evidence non-empty
2. `ntp_external_does_not_fire_for_non_ot_source` — negative EC-001, asserts empty
3. `ntp_external_does_not_fire_for_intra_ot_traffic` — negative EC-002, asserts empty
4. `ntp_external_flags_multicast_destination` — EC-003, asserts `len == 1`

Tests use `run_all` (not direct `detect`) — confirms wiring through `mod.rs`.
Helper `make_ntp_flow_obs` correctly sets `proto: 17` (UDP) in the FlowKey and
`in_ot_zone` flags per scenario. All assertions carry descriptive failure messages with AC/EC IDs.

Note: tests don't use `insta::assert_snapshot!` — they are assertion-based, not snapshot-based.
The commit message calls them "snapshot tests" but they are actually `assert_eq!` / `assert!`
tests in `tests/snapshot.rs`. This is consistent with how BC-2.x tests in that file work.
Not a finding.

### Wire-up (mod.rs)

**PASS.**
- `mod ntp_external;` declared (alphabetically ordered)
- `ntp_external::METADATA` included in `catalog()`
- `ntp_external::detect(obs, ot_subnets)` called in `run_all()`
- `run_all` output sorted by severity desc then id asc — insertion position correct

### RULES.md

**PASS.** Count updated from 14 to 15. New rule entry placed correctly in the index
(after `boundary.dns_resolver`, before `recon.port_scan`). Rule body matches `METADATA`
const content exactly.

### Demo Evidence

**PASS.** Two recordings committed:
- `ac-001-ntp-detection.{tape,gif,webm}` — covers AC-001 and the two negative cases (EC-001, EC-002)
- `ec-003-multicast.{tape,gif,webm}` — covers EC-003

`evidence-report.md` links both recordings with coverage map. All ACs have >= 1 recording.

### Lint / Format

**PASS.** All checks clean per commit `3ce7100` message: 166 tests, clippy clean, fmt clean,
POL-12 0 violations.

---

## Triage Routing

No findings to route. All categories: PASS.

---

## Verdict

**APPROVE**

Zero blocking findings. Zero substantive findings. Zero nitpicks. The implementation is a
clean, self-contained sibling of `boundary.dns_resolver` with full AC/EC coverage, correct
wiring, and committed demo evidence. Ready to merge.
