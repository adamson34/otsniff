# New rule-based findings

## Problem

Three categories of issue real OT networks routinely have, that otsniff
currently doesn't catch as deterministic findings:

1. **SMBv1 traffic.** Deprecated by Microsoft 2014, blocked by Windows
   Defender, but persistent in OT because of legacy HMIs, old engineering
   workstations, and Windows-CE-class controllers. EternalBlue / WannaCry
   exploited SMBv1 specifically; its presence is a known liability.
2. **Stale TLS versions** (TLS 1.0 / 1.1, SSL 3.0). All deprecated.
   Modern Windows blocks them by default. Their presence on OT signals
   either unsupported clients or misconfigured services worth replacing.
3. **DNS to non-OT resolver.** Boundary-hygiene issue Claude flagged on
   the 4SICS-20 run that the rules layer doesn't currently catch — an OT
   host using a resolver outside the OT zone leaks query patterns and
   trusts an external resolver's answers.

Each is small to detect, fires on data we already parse, and adds a
real category of finding to every busy capture.

## What we detect

### SMBv1

SMB framing on tcp/445 (or legacy tcp/139 over NBSS):

- TCP payload starts with NBSS session message header (4 bytes:
  `0x00 0x00 length_hi length_lo`)
- Followed by SMB1 magic `\xFF SMB` (`0xFF 0x53 0x4D 0x42`) at offset 4
- OR `\xFF SMB` at offset 0 if NBSS prefix is absent

Any host that sends an SMB1-magic packet at all is flagged. Modern
Windows clients refuse to speak SMB1 by default — its presence
indicates a legacy client / server worth identifying.

### Stale TLS versions

TLS ClientHello at the start of a TCP/443 (or 8443) connection:

- Record layer: byte 0 = `0x16` (handshake), bytes 1-2 = legacy record
  version, bytes 3-4 = length
- Handshake layer: byte 5 = `0x01` (ClientHello), bytes 6-8 = length,
  bytes 9-10 = legacy_version

`legacy_version` of `0x0300` (SSL 3.0), `0x0301` (TLS 1.0), or `0x0302`
(TLS 1.1) flags. `0x0303` (TLS 1.2) and `0x0304` (TLS 1.3) pass.

Note: TLS 1.3 ClientHellos use `0x0303` in legacy_version (compat) and
specify 1.3 in the supported_versions extension. We don't parse
extensions — `legacy_version >= 0x0303` is "modern enough" for the v0.1
finding.

### DNS to non-OT resolver

For each logical flow (we already aggregate by 4-tuple): if `dst_port
== 53` AND `src` is in any configured OT subnet AND `dst` is NOT in any
configured OT subnet → flag the (src, dst) pair.

This overlaps with the existing internet-egress finding when `dst` is
public, but they have different framings: egress is about *anything*
leaving OT to the internet; this finding is specifically about DNS
resolver hygiene (a host using an IT-zone resolver also fires this but
not egress).

## Output

Three new findings, each with summary, evidence, recommendation, and
playbook (per the P0-7 contract).

### `compat.smbv1` — High severity

```
[High] SMBv1 traffic on the wire

3 host(s) seen sending SMB1-magic frames on tcp/445. SMBv1 is
deprecated, blocked by default in modern Windows, and a known
exploitation surface (WannaCry / EternalBlue). Its presence indicates
legacy clients, legacy servers, or both.

Evidence:
  192.168.2.137 -> 192.168.2.101:445 (4,231 packets)
  ...

Recommendation:
  Identify the legacy hosts. Migrate to SMBv2/v3, retire the legacy
  device, or isolate it on a hardened management VLAN. Enabling
  "SMB1 disabled" via Group Policy on Windows hosts is a one-step
  improvement for any modern host that's still negotiating it.

Playbook:
  1. Identify the source / destination hosts physically...
  2. For Windows hosts: disable SMB1 via Group Policy or
     PowerShell (`Disable-WindowsOptionalFeature ... SMB1Protocol`)
  3. For embedded / OT-class devices that can only speak SMB1:
     isolate on a management VLAN, document the exception
  4. Patch / decommission known-vulnerable Windows versions
     (Windows 7, Server 2008) that depend on SMB1 for file shares
```

### `compat.stale_tls` — Medium severity

```
[Medium] Deprecated TLS versions observed (TLS 1.0 / 1.1)

15 ClientHello(s) using TLS 1.0 or earlier seen across 4 host pair(s).
These versions are deprecated and blocked by default in modern
Windows / browsers. Their presence indicates legacy clients (older
Java runtimes, embedded devices) or legacy services.

Evidence:
  192.168.2.137 -> 192.168.10.5:443 : TLS 1.0 (8 hellos)
  ...

Playbook:
  1. Identify the source hosts and the services they're connecting
     to...
  2. For Windows clients: ensure TLS 1.2+ is enabled in Schannel
     and TLS 1.0/1.1 is disabled
  3. For services: upgrade the TLS implementation; if it's an
     embedded device that only supports TLS 1.0, isolate it
  4. Treat any captured certificates from these connections as
     suspect — the cipher suites available with TLS 1.0/1.1 are
     vulnerable
```

### `boundary.dns_resolver` — Medium severity

```
[Medium] DNS queries to a non-OT resolver

3 OT host(s) sending DNS queries to resolvers outside the configured
OT subnets. Cross-zone DNS leaks query patterns to the IT side and
trusts an external resolver's answers; both belong on the OT side
under change control.

Evidence:
  10.10.10.5 -> 8.8.8.8:53 (UDP, 247 queries)
  10.10.10.10 -> 1.1.1.1:53 (UDP, 89 queries)

Playbook:
  1. Identify the host's configured DNS server (Windows: ipconfig
     /all; Linux: /etc/resolv.conf, systemd-resolve --status)
  2. Verify whether an in-zone resolver exists. If yes, point the
     OT host at it
  3. If no in-zone resolver: stand one up in the OT zone or DMZ
     with strict upstream relationships (only resolves a known set
     of names)
  4. Add an outbound UDP/53 deny rule at the IT/OT boundary for OT
     subnets that aren't the resolver itself
```

## Implementation

### `src/observe.rs` — new observation collections

```rust
pub struct Observations {
    // ... existing fields
    /// Map of (src, dst, dst_port) → SMBv1 packet count for that pair.
    /// HashMap rather than Vec to bound memory on busy SMB networks.
    pub smbv1_packets: HashMap<(IpAddr, IpAddr, u16), u64>,
    /// Map of (src, dst, dst_port, legacy_version) → ClientHello count.
    pub tls_client_hellos: HashMap<(IpAddr, IpAddr, u16, u16), u64>,
}
```

In `observe_tcp`:

- If `dst_port == 445 || src_port == 445 || dst_port == 139 || src_port == 139`:
  check payload for SMB1 magic, increment counter
- If `dst_port == 443 || dst_port == 8443`:
  check payload for TLS ClientHello, extract `legacy_version`, increment counter

### `src/findings/smbv1.rs`, `stale_tls.rs`, `dns_resolver.rs`

Three new modules, one per finding. Each implements
`pub fn detect(obs, ot_subnets) -> Vec<Finding>`. Wired into
`findings/mod.rs::run_all`.

### Tests

- Unit tests on the SMB1 and TLS payload-byte recognition (raw fixtures)
- Snapshot fixture extended with synthetic SMB1 / TLS / DNS-resolver
  events so all three findings fire in the deterministic test
- The existing `every_finding_has_a_non_empty_playbook` invariant
  catches detector-without-playbook regressions

## Out of scope

- **SMBv2/v3 vulnerability detection.** Different work — would need to
  parse SMB capability flags and check against known CVEs. v0.1 only
  flags SMBv1 (the categorical bad).
- **TLS cipher-suite analysis.** ClientHello includes a list of cipher
  suites. We don't decode the list — that's a different finding (weak
  cipher offer / acceptance). Roadmap candidate.
- **DNS query content analysis.** Just counts queries to non-OT
  resolvers. Doesn't decode the QNAME or check against suspicious-domain
  watchlists. Different finding (could go in the payload-aware-findings
  P2-3 work).
- **Active client SMB version negotiation tracking.** A modern Windows
  client that negotiates SMBv2/v3 may still send an initial SMBv1
  Negotiate Request to enumerate dialects. Our heuristic fires on
  `\xFF SMB` anywhere; a sophisticated detector would distinguish
  initial negotiation from active SMBv1 sessions. Acceptable false-
  positive rate for v0.1 — flag any presence and let the responder
  verify.
