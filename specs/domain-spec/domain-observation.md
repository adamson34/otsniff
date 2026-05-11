---
artifact_type: domain-spec-shard
shard: observation
project: otsniff
traces_to: L2-INDEX.md
---

# Domain shard: Observation context

The Observation context turns raw packet bytes into typed,
deterministic state. It owns the protocol-recognition logic and the
accumulator struct that downstream contexts read.

## Capabilities served

- CAP-001 — Read PCAP / PCAPNG, extract L2–L4 metadata
- CAP-002 — Protocol-level signal recognition (Modbus, ENIP, S7Comm, DHCP, plaintext creds, SMBv1, TLS legacy)
- CAP-003 — Accumulate into typed single-pass state

## Entities

### `Packet` (value object — immutable)

Per-packet record. Owned payload (ADR-0004) — no lifetime contagion.

```
Packet
├── ts: DateTime<Utc>            — capture timestamp
├── src_mac, dst_mac: [u8; 6]    — Ethernet addresses
├── src_ip, dst_ip: IpAddr       — IPv4 or IPv6
├── src_port, dst_port: u16
├── transport: Transport         — Tcp | Udp | Other(u8)
└── payload: Vec<u8>             — owned bytes (no &[u8])
```

### `Transport` (enum)

```
Transport ::= Tcp | Udp | Other(u8)
```

Protocol number stays opaque (`Other(u8)`) — we observe but don't
parse non-TCP/UDP. ICMP, SCTP, etc. count toward `total_packets` and
contribute to `mac_frame_counts` but produce no flow record.

### `Observations` (aggregate root — mutable during accumulation, immutable after `Observer::finish()`)

The central state struct. Pass 2 lists all 16 fields; the load-bearing ones:

```
Observations
├── hosts: HashMap<IpAddr, HostObs>
├── flows: HashMap<String, FlowObs>
├── modbus_events / enip_events / s7_events: Vec<Event>
├── cred_events: Vec<CredEvent>          — see Privacy domain for #[serde(skip)] discussion
├── external_flows: HashMap<String, ExternalFlow>
├── smbv1_packets, tls_client_hellos: HashMap<tuple, u64>
├── hostnames: BTreeMap<IpAddr, String>
├── mac_frame_counts: BTreeMap<[u8;6], u64>
├── broadcast_frames: u64
├── first_ts, last_ts: Option<DateTime<Utc>>
├── total_packets, total_bytes: u64
└── (ot_subnets is on Observer, not Observations — see Pass 6 §"Where the passes disagree")
```

### `HostObs` (value object — per host)

```
HostObs
├── ip: IpAddr
├── macs: Vec<[u8; 6]>             — a host can have multiple over time
├── protocols: HashSet<String>     — port-derived labels
├── first_seen, last_seen: DateTime<Utc>
├── packets, bytes: u64
└── in_ot_zone: bool               — computed once vs ot_subnets
```

### `FlowObs` (value object — per logical flow)

```
FlowObs
├── key: FlowKey { src, dst, dst_port, proto }
│       └── NOTE: src_port intentionally absent (CAP-003 invariant)
├── packets, bytes: u64
├── first_seen, last_seen: DateTime<Utc>
├── label: Option<String>          — "modbus", "http", "dns", "openvpn", ...
└── unique_src_ports: HashSet<u16> — distinct connections in this flow
```

The `connections()` method (= `unique_src_ports.len()`) is what the
reports show as "Conns" column.

### Protocol-specific event records

```
ModbusEvent { ts, src, dst, function_code, label, engineering_class }
EnipEvent   { ts, src, dst, command, command_label, cip_service, engineering_class }
S7Event     { ts, src, dst, function_code, label, engineering_class, read_class }
CredEvent   { ts, src, dst, dst_port, kind: CredKind, note (skipped) }
ExternalFlow{ src, dst, dst_port, proto, packets, bytes }
```

`CredKind ::= FtpAuth | TelnetSession | HttpBasic | Snmpv1v2c`

`CredEvent.note` is `#[serde(skip)]` and never renders — see Privacy domain.

## Relationships

```
Packet (transient)
  ├─stream of─▶ Observer
                └─ writes to ─▶ Observations
                                ├─ contains ─▶ HostObs (per IP)
                                ├─ contains ─▶ FlowObs (per logical flow)
                                └─ contains ─▶ Event lists (per protocol)
```

After `Observer::finish()` the resulting `Observations` is immutable
and flows to the Analysis context.

## Processes

### Single-pass accumulation

For every `Packet`:

1. Increment `total_packets` and add payload length to `total_bytes`
2. Update `mac_frame_counts` and `broadcast_frames`
3. Update `first_ts` / `last_ts`
4. `update_host(src_ip, src_mac, pkt)` and `update_host(dst_ip, dst_mac, pkt)`
5. Compute `FlowKey` and update or create the matching `FlowObs`
6. Per-transport dispatch:
   - TCP → `observe_tcp(pkt)`: dispatch to Modbus / ENIP / S7Comm / cred / SMBv1 / TLS recognizers based on port
   - UDP → `observe_udp(pkt)`: dispatch to DHCP option-12 / SNMP recognizers
7. If `src_ip` is in any OT subnet AND `dst_ip` is public → append to `external_flows`

### Protocol-recognition rules (function-code-level only, ADR-0002)

| Protocol | Port | Recognizer | Output |
|---|---|---|---|
| Modbus/TCP | tcp/502 | `parse::modbus::parse` (MBAP frame + function code) | `ModbusEvent` with engineering flag |
| EtherNet/IP CIP | tcp/44818 | `parse::enip::parse_header` + `engineering_class_cip` | `EnipEvent` with optional CIP service label |
| S7Comm | tcp/102 | `parse::s7comm::parse` (TPKT + COTP + S7 header) | `S7Event` with engineering/read flag |
| DHCP | udp/67,68 | `parse::dhcp::parse` (magic cookie + option 12) | (IP, hostname) → `obs.hostnames` |
| FTP | tcp/21 | "USER " / "PASS " prefix scan | `CredEvent { kind: FtpAuth, note }` |
| Telnet | tcp/23 | Any non-empty payload | `CredEvent { kind: TelnetSession }` |
| HTTP | tcp/80,8080 | Substring `Authorization: Basic ` | `CredEvent { kind: HttpBasic, note }` |
| SNMP | udp/161,162 | BER seq + version 0 or 1 | `CredEvent { kind: Snmpv1v2c }` |
| SMBv1 | tcp/445,139 | `\xFF SMB` magic at offset 0 or 4 | Increment `smbv1_packets[key]` |
| TLS ClientHello | tcp/443,8443 | record_type=0x16 + handshake=0x01 | Increment `tls_client_hellos[(src,dst,port,version)]` |

## Invariants

| Invariant | Source |
|---|---|
| **Single-pass.** Each packet touched exactly once. Memory grows in unique hosts/flows/events, not raw packet count. | NFR-PERF.001 |
| **Flow-key excludes src_port.** Two TCP connections from the same client to the same server:port aggregate into one logical flow. | `docs/specs/flow-grouping.md` |
| **Determinism.** `BTreeMap` over `HashMap` where iteration order matters; events appended in observation order. | NFR-REL.001 |
| **Owned packet payloads.** `Packet::payload: Vec<u8>` — never `&[u8]`. | ADR-0004 |
| **Function-code-level fidelity.** Parsers extract only the function code + label + classification needed by the findings layer; no full PDU decoding. | ADR-0002 |

## Open issues (handed to PRD)

- **OQ-5 — `cred_events` unboundedness.** This Vec scales linearly with raw packets, not unique events. For long-duration Telnet captures, memory grows linearly. Should rollup-at-observation-time land in v0.4? See L-P1-002.

## Known gaps in coverage (per Phase 0 B.5 audit)

- `src/oui.rs` is a blind spot — no per-vendor entity in the L2 model. The OUI lookup is referenced indirectly through `infer_role` in the Analysis context. If we ever surface a "Vendor" entity to the user, the L2 model needs it.
