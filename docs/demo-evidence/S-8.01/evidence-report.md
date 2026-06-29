# S-8.01 Demo Evidence Report

Story: mDNS / NetBIOS-NS / LLMNR hostname extraction
Branch: `feature/S-8.01-hostname-extraction`
Recorded: 2026-06-29

## Summary

All acceptance criteria are covered by two VHS terminal recordings against a
synthetic PCAP fixture. The PCAP was hand-crafted with pure Python (stdlib
`struct` only, no scapy) to contain one packet per protocol. All tape files and
fixture scripts are free of absolute paths (POL-12 compliant).

---

## AC Coverage

### AC-001 — mDNS A-record hostname extraction

**Demo:** `AC-001-005-hostname-extraction` (success path)

The synthetic PCAP contains a valid mDNS response (UDP/5353) from `192.168.10.5`
advertising `HMI-LINE-3.local.` → `192.168.10.5`. After `otsniff analyze`, the
JSON inventory shows:

```json
{
  "ip": "192.168.10.5",
  "hostname": "HMI-LINE-3"
}
```

The `.local.` suffix is stripped by `src/parse/mdns.rs` per the AC-001
normalization rule (BC-1.02.013 precondition).

**Artifacts:**
- `docs/demo-evidence/S-8.01/AC-001-005-hostname-extraction.gif`
- `docs/demo-evidence/S-8.01/AC-001-005-hostname-extraction.webm`
- `docs/demo-evidence/S-8.01/AC-001-005-hostname-extraction.tape`

---

### AC-002 — NetBIOS-NS workstation-name extraction

**Demo:** `AC-001-005-hostname-extraction` (success path, same recording)

The synthetic PCAP contains a valid NBNS Registration Request (UDP/137) from
`192.168.10.10` for `PLC-LINE3`. After `otsniff analyze`, the JSON inventory
shows:

```json
{
  "ip": "192.168.10.10",
  "hostname": "PLC-LINE3"
}
```

Trailing spaces and the 16th suffix byte are stripped by `src/parse/netbios.rs`
per AC-002 (BC-1.02.011 postcondition).

**Artifacts:** same as AC-001.

---

### AC-003 — LLMNR A-record hostname extraction

**Demo:** `AC-001-005-hostname-extraction` (success path, same recording)

The synthetic PCAP contains a valid LLMNR response (UDP/5355, QR=1) from
`192.168.10.20` for `ENG-WS-01` → `192.168.10.20`. After `otsniff analyze`,
the JSON inventory shows:

```json
{
  "ip": "192.168.10.20",
  "hostname": "ENG-WS-01"
}
```

The trailing dot is stripped by `src/parse/llmnr.rs` per AC-003 (BC-1.02.012
postcondition).

**Artifacts:** same as AC-001.

---

### AC-004 — Observer wiring

**Demo:** `AC-001-005-hostname-extraction` (success path, same recording)

All three hostnames appear in the single-pass `otsniff analyze` output,
confirming that `src/observe.rs` `observe_udp` dispatches to all three parsers
(UDP/5353, UDP/137, UDP/5355) and inserts results into `obs.hostnames` via
last-write-wins `BTreeMap::insert` (BC-1.02.013 postcondition).

**Artifacts:** same as AC-001.

---

### AC-005 — Existing consumers automatically enriched

**Demo:** `AC-001-005-hostname-extraction` (success path, same recording)

The `jq` query `'.inventory[] | select(.hostname) | {ip,hostname}'` shows all
three hostnames in the inventory struct consumed by `src/inventory.rs` and
`src/findings/`. No changes were required to those modules; the enrichment is
automatic because all three new parsers write into the same `obs.hostnames` map.

**Artifacts:** same as AC-001.

---

### AC-006 — Privacy invariant unbroken

**Approach:** AC-006 is covered by the existing automated test
`invariant_no_real_values_reach_ai_provider` in `tests/snapshot.rs`, which
exercises the full scrub + leak-check pipeline. Hostnames from all three new
sources enter `obs.hostnames` and are therefore scrubbed via the existing
`name_NNN` pseudonym class (ADR-0006). No demo recording is needed for this AC;
the test suite enforces it on every `cargo test` run.

**Evidence:** `cargo test --test snapshot invariant` (CI-green per branch status).

---

### EC-001 — Malformed / truncated packets handled gracefully

**Demo:** `EC-001-malformed-graceful` (error path)

A second synthetic PCAP contains:
1. A truncated mDNS payload (8 bytes, below the 12-byte DNS header minimum)
2. An LLMNR response whose answer owner name is a DNS compression pointer
   (0xC0 0x0C) — rejected by the no-compression-pointer rule
3. An NBNS packet with OPCODE=0 (Name Query, not Registration) — rejected by
   the OPCODE check

`otsniff analyze` exits 0 and produces a valid report. The `jq` query confirms
that `[.inventory[].hostname] | map(select(. != null)) | length` equals `0` —
no hostname was extracted from any malformed packet.

**Artifacts:**
- `docs/demo-evidence/S-8.01/EC-001-malformed-graceful.gif`
- `docs/demo-evidence/S-8.01/EC-001-malformed-graceful.webm`
- `docs/demo-evidence/S-8.01/EC-001-malformed-graceful.tape`

---

## Fixture

| File | Purpose |
|------|---------|
| `fixtures/make_pcap.py` | Python stdlib PCAP generator (no third-party deps) |
| `fixtures/hostname-extraction.pcap` | Success path: mDNS + NBNS + LLMNR packets |
| `fixtures/malformed-hostname.pcap` | Error path: truncated + malformed packets |

All paths in `.tape` files are relative to the worktree root; no absolute paths
are present (POL-12 compliant). VHS recordings run with `vhs
docs/demo-evidence/S-8.01/<name>.tape` from the worktree root.

---

## Coverage Matrix

| AC | Recording | Path Covered |
|----|-----------|-------------|
| AC-001 mDNS extraction | `AC-001-005-hostname-extraction` | success |
| AC-002 NetBIOS-NS extraction | `AC-001-005-hostname-extraction` | success |
| AC-003 LLMNR extraction | `AC-001-005-hostname-extraction` | success |
| AC-004 Observer wiring | `AC-001-005-hostname-extraction` | success |
| AC-005 Consumer enrichment | `AC-001-005-hostname-extraction` | success |
| AC-006 Privacy invariant | cargo test (automated) | N/A |
| EC-001 Malformed graceful | `EC-001-malformed-graceful` | error |
