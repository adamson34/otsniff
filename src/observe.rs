//! Single-pass observation layer.
//!
//! Walks every packet, accumulates per-host and per-flow state plus
//! interesting events (Modbus writes, ENIP/CIP engineering services,
//! plaintext credentials, external egress). The findings layer reads this
//! struct after iteration completes — keeps the parse loop tight.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::Serialize;

use crate::parse::{dhcp, dnp3, enip, ldap, modbus, rdp, s7comm};
use crate::pcap::{Packet, Transport};

#[derive(Debug, Clone, Serialize)]
pub struct HostObs {
    pub ip: IpAddr,
    pub macs: Vec<[u8; 6]>,
    pub protocols: HashSet<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packets: u64,
    pub bytes: u64,
    pub in_ot_zone: bool,
}

/// Logical flow key: aggregates by source IP, destination IP+port, and
/// transport protocol. Source port is intentionally excluded — TCP/UDP
/// source ports are ephemeral, so including them in the key produced a
/// noisy comms matrix where each TCP connection appeared as a separate
/// flow. See docs/specs/flow-grouping.md.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowObs {
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub label: Option<String>,
    /// Distinct source ports observed for this logical flow. The size of
    /// this set is the number of TCP/UDP connections (or unconnected
    /// datagram sources) that contributed to the flow. Bursts of unique
    /// connections are themselves a signal — typical of probe / scan /
    /// fuzz traffic.
    pub unique_src_ports: HashSet<u16>,
}

impl FlowObs {
    /// Number of distinct source ports seen for this logical flow.
    pub fn connections(&self) -> usize {
        self.unique_src_ports.len()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModbusEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub function_code: u8,
    pub label: String,
    pub engineering_class: bool,
}

/// Per-`(src, dst)` Modbus flow summary, aggregated eagerly by the observer.
///
/// `unit_ids` accumulates every distinct Modbus unit ID seen in requests from
/// `src` to `dst` within the capture. Used by `findings::modbus_recon` to
/// detect unit-ID sweep / discovery patterns (S-2.11 AC-001, BC-1.02.009).
///
/// Populated at the Modbus event-push site — implementer's Step 4. Initialized
/// empty here so all snapshot tests and existing consumers compile unchanged.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ModbusFlowSummary {
    pub unit_ids: BTreeSet<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnipEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub command: u16,
    pub command_label: String,
    pub cip_service: Option<String>,
    pub engineering_class: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct S7Event {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub function_code: u8,
    pub label: String,
    pub engineering_class: bool,
    pub read_class: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dnp3Event {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub function_code: u8,
    pub engineering_class: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub kind: CredKind,
    /// Number of times this (src, dst, dst_port, kind) tuple has been
    /// observed. Initialized to 1; incremented by the dedup helper
    /// `Observer::record_cred_event` when a duplicate key is seen.
    /// See BC-1.03.007 (S-2.02).
    pub count: u32,
    /// Internal-only diagnostic captured from the wire. May contain
    /// CIP-011 High-BCSI bytes (literal `USER` lines, b64-encoded
    /// HTTP Basic credentials). MUST NOT reach any rendered output
    /// without first being routed through a scrub class — see
    /// `docs/audits/scrub-audit-cip011.md` Finding #1. The
    /// `#[serde(skip)]` keeps it out of any JSON path even if a
    /// future feature accidentally serializes the parent struct.
    #[serde(skip)]
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum CredKind {
    FtpAuth,
    TelnetSession,
    HttpBasic,
    Snmpv1v2c,
}

/// NTLM protocol version inferred from the NEGOTIATE_MESSAGE flags field.
///
/// `V1` — `NTLMSSP_NEGOTIATE_NTLM` (bit 9) is set and
///        `NTLMSSP_NEGOTIATE_NTLM2_KEY` (bit 19) is unset.
/// `V2` — both `NTLMSSP_NEGOTIATE_NTLM` and `NTLMSSP_NEGOTIATE_NTLM2_KEY`
///        are set.
///
/// See S-2.06 AC-001 (BC-1.03.006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NtlmVersion {
    V1,
    V2,
}

/// One NTLMSSP NEGOTIATE_MESSAGE (message type 1) observed in an SMB, HTTP,
/// or RPC payload.
///
/// Populated by `Observer::observe_tcp` when the `NTLMSSP\0` signature is
/// found in a TCP payload and the flags field is decoded. See S-2.06
/// AC-001 (BC-1.03.006).
#[derive(Debug, Clone, Serialize)]
pub struct NtlmEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub version: NtlmVersion,
}

/// Result of parsing an NTLMSSP NEGOTIATE_MESSAGE (message type 1).
///
/// Returned by `recognize_ntlm_negotiate` when the `NTLMSSP\0` signature is
/// found at the start of the payload, message type is 1 (NEGOTIATE), and the
/// flags field can be decoded. The caller promotes this into an `NtlmEvent`.
///
/// See S-2.06 AC-001 (BC-1.03.006).
pub(crate) struct NtlmNegotiateRecognized {
    /// Protocol version inferred from the NEGOTIATE_MESSAGE flags field
    /// (offset 12, 4 bytes little-endian).
    pub version: NtlmVersion,
}

/// Attempt to parse an NTLMSSP NEGOTIATE_MESSAGE from a raw TCP payload.
///
/// Returns `Some(NtlmNegotiateRecognized)` iff:
/// - bytes 0-7 == `b"NTLMSSP\0"` (the NTLMSSP signature)
/// - bytes 8-11 == `[0x01, 0x00, 0x00, 0x00]` (MessageType = 1, NEGOTIATE)
/// - bytes 12-15 are present (the NegotiateFlags field)
///
/// Version classification from the flags (MS-NLMP §2.2.2.5 / §2.2.1.1):
/// - `NTLMSSP_NEGOTIATE_NTLM2_KEY` (bit 19, 0x00080000) set → V2
/// - `NTLMSSP_NEGOTIATE_NTLM` (bit 9, 0x00000200) set, NTLM2_KEY unset → V1
///
/// Returns `None` for any other payload (wrong signature, wrong message type,
/// truncated, or flags indicate neither V1 nor V2). See EC-002.
pub(crate) fn recognize_ntlm_negotiate(payload: &[u8]) -> Option<NtlmNegotiateRecognized> {
    // Need at least 16 bytes: 8-byte signature + 4-byte MessageType + 4-byte flags.
    if payload.len() < 16 {
        return None;
    }
    // Check NTLMSSP signature: bytes 0-7 == b"NTLMSSP\0".
    if &payload[0..8] != b"NTLMSSP\0" {
        return None;
    }
    // MessageType must be 1 (NEGOTIATE). Bytes 8-11, little-endian u32.
    let msg_type = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    if msg_type != 1 {
        return None;
    }
    // NegotiateFlags at bytes 12-15, little-endian u32.
    let flags = u32::from_le_bytes(payload[12..16].try_into().unwrap());

    // Classify version from flags (MS-NLMP §2.2.2.5 / §2.2.1.1).
    //   NTLMSSP_NEGOTIATE_NTLM2_KEY (bit 19) = 0x00080000 → V2
    //   NTLMSSP_NEGOTIATE_NTLM      (bit 9)  = 0x00000200 → V1 (NTLM2_KEY unset)
    const NTLM2_KEY: u32 = 0x0008_0000;
    const NTLM: u32 = 0x0000_0200;

    let version = if (flags & NTLM2_KEY) != 0 {
        NtlmVersion::V2
    } else if (flags & NTLM) != 0 {
        NtlmVersion::V1
    } else {
        // Neither NTLM bit is set — not a genuine NTLM auth attempt.
        return None;
    };

    Some(NtlmNegotiateRecognized { version })
}

/// One RDP Connection Confirm PDU (X.224 type 0xD0) observed on tcp/3389.
///
/// Populated by `Observer::observe_tcp` when `parse::rdp::recognize_connection_confirm`
/// succeeds on the payload. `selected_protocol` carries the value from the
/// `RDP_NEG_RSP` block; `selected_protocol & 0x01 == 0` means no NLA/SSL was
/// negotiated — see S-2.08 AC-001 (BC-1.04.004).
#[derive(Debug, Clone, Serialize)]
pub struct RdpEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub selected_protocol: u32,
}

/// One LDAP `BindRequest` with `SimpleAuthentication` observed on the wire.
///
/// Populated by `Observer::observe_tcp` for tcp/389 (and non-standard LDAP
/// ports). The `used_starttls` flag is set by the caller after inspecting the
/// flow's STARTTLS exchange history — see AC-003 (S-2.05).
#[derive(Debug, Clone, Serialize)]
pub struct LdapBindEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    /// LDAP version declared in the `BindRequest` (usually 3).
    pub version: u8,
    /// `true` when a successful STARTTLS exchange preceded this bind on the
    /// same flow — the finding suppressor reads this field (AC-003).
    pub used_starttls: bool,
    /// `true` when the bind uses an empty DN and empty password (anonymous
    /// bind). Anonymous binds are not a credential-leak signal — EC-003.
    /// The parser surfaces this; the finding layer suppresses it.
    pub anonymous: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalFlow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Observations {
    pub hosts: HashMap<IpAddr, HostObs>,
    pub flows: HashMap<String, FlowObs>,
    pub modbus_events: Vec<ModbusEvent>,
    /// Per-`(src, dst)` Modbus unit-ID accumulator. Keyed by `(src_ip, dst_ip)`;
    /// value holds the set of distinct unit IDs seen for that pair within the
    /// capture. Populated at the Modbus event-push site (implementer's Step 4
    /// for S-2.11). Initialized empty so all existing consumers compile without
    /// change.
    pub modbus_flow_summary: BTreeMap<(IpAddr, IpAddr), ModbusFlowSummary>,
    pub enip_events: Vec<EnipEvent>,
    pub s7_events: Vec<S7Event>,
    pub dnp3_events: Vec<Dnp3Event>,
    pub ntlm_events: Vec<NtlmEvent>,
    pub ldap_bind_events: Vec<LdapBindEvent>,
    /// RDP Connection Confirm events observed on tcp/3389. Populated by the
    /// implementer in Step 4 (S-2.08); initialized empty here so snapshot
    /// tests and all existing consumers compile without change.
    pub rdp_events: Vec<RdpEvent>,
    pub cred_events: Vec<CredEvent>,
    /// Dedup index for `cred_events`. Maps `(src, dst, dst_port, kind)` to the
    /// index into `cred_events`. Populated and maintained exclusively by
    /// `Observer::record_cred_event` (BC-1.03.007). Skipped during serialization
    /// because it is internal bookkeeping, not report content.
    #[serde(skip)]
    pub cred_events_index: HashMap<(IpAddr, IpAddr, u16, CredKind), usize>,
    pub external_flows: HashMap<String, ExternalFlow>,
    /// Map of (src, dst, dst_port) → SMBv1 packet count. Bounded by
    /// distinct host pairs, not raw packet count, so a busy SMB
    /// network doesn't blow this up.
    pub smbv1_packets: HashMap<(IpAddr, IpAddr, u16), u64>,
    /// Map of (src, dst, dst_port, legacy_version) → TLS ClientHello
    /// count. legacy_version is the on-the-wire u16 (0x0301 = TLS 1.0,
    /// 0x0302 = TLS 1.1, 0x0303 = TLS 1.2 / 1.3).
    pub tls_client_hellos: HashMap<(IpAddr, IpAddr, u16, u16), u64>,
    /// Map of (src, dst, dst_port) → cipher suite codes advertised in
    /// TLS ClientHellos on that flow (S-2.07, BC-1.04.003). Each
    /// ClientHello's cipher_suites list is appended; duplicates are
    /// expected when the same flow sends multiple hellos. The detector
    /// (`weak_tls_cipher`) reads this to identify RC4 / DES / NULL
    /// suites. Populated by the implementer in Step 4; initialized empty
    /// here so snapshot tests and all existing consumers compile without
    /// change.
    pub tls_cipher_suites: HashMap<(IpAddr, IpAddr, u16), Vec<u16>>,
    /// IP → hostname, populated from passive sources (DHCP option 12 today;
    /// mDNS / NetBIOS planned). Last-write-wins if multiple sources name
    /// the same IP, but in practice DHCP is the only source for now.
    pub hostnames: BTreeMap<IpAddr, String>,
    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
    pub total_packets: u64,
    pub total_bytes: u64,
    /// Frames where each MAC appeared as src or dst. BTreeMap so iteration
    /// is deterministic for snapshots and the capture-source classifier.
    /// A single frame contributes 1 to both endpoints' counts (or 1 if
    /// src and dst are the same MAC, which would be unusual).
    pub mac_frame_counts: BTreeMap<[u8; 6], u64>,
    /// Frames whose destination MAC was broadcast (`ff:ff:ff:ff:ff:ff`)
    /// or had the multicast bit set. Used by the capture-source detector
    /// as a SPAN signal.
    pub broadcast_frames: u64,
}

pub struct Observer {
    ot_subnets: Vec<IpNet>,
    obs: Observations,
    /// STARTTLS state per logical LDAP flow keyed by
    /// `(src_ip, dst_ip, src_port, dst_port)`. The value is set to `true`
    /// when a successful STARTTLS extended-operation response (resultCode 0)
    /// is observed on that flow. The observer reads this when emitting an
    /// `LdapBindEvent` so the finding layer can suppress after-STARTTLS binds
    /// (AC-003 / BC-3.01.005).
    ldap_starttls_flows: HashMap<(IpAddr, IpAddr, u16, u16), bool>,
}

impl Observer {
    pub fn new(ot_subnets: Vec<IpNet>) -> Self {
        Self {
            ot_subnets,
            obs: Observations::default(),
            ldap_starttls_flows: HashMap::new(),
        }
    }

    pub fn finish(self) -> Observations {
        self.obs
    }

    pub fn observe(&mut self, pkt: &Packet) {
        let bytes = pkt.payload.len() as u64;
        self.obs.total_packets += 1;
        self.obs.total_bytes += bytes;

        // Capture-source signals: per-MAC frame counts + broadcast tally.
        // A single frame contributes 1 to src_mac and 1 to dst_mac
        // (or just 1 if src == dst, which is rare).
        if pkt.src_mac != [0u8; 6] {
            *self.obs.mac_frame_counts.entry(pkt.src_mac).or_insert(0) += 1;
        }
        if pkt.dst_mac != [0u8; 6] && pkt.dst_mac != pkt.src_mac {
            *self.obs.mac_frame_counts.entry(pkt.dst_mac).or_insert(0) += 1;
        }
        if is_broadcast_or_multicast(&pkt.dst_mac) {
            self.obs.broadcast_frames += 1;
        }
        self.obs.first_ts.get_or_insert(pkt.ts);
        self.obs.last_ts = Some(pkt.ts);

        self.update_host(pkt.src_ip, pkt.src_mac, pkt, bytes);
        self.update_host(pkt.dst_ip, pkt.dst_mac, pkt, bytes);

        let proto_byte = match pkt.transport {
            Transport::Tcp => 6,
            Transport::Udp => 17,
            Transport::Other(p) => p,
        };
        let key = FlowKey {
            src: pkt.src_ip,
            dst: pkt.dst_ip,
            dst_port: pkt.dst_port,
            proto: proto_byte,
        };
        let key_str = flow_key_str(&key);
        let label = classify_flow(pkt);
        let src_port = pkt.src_port;
        self.obs
            .flows
            .entry(key_str)
            .and_modify(|f| {
                f.packets += 1;
                f.bytes += bytes;
                f.last_seen = pkt.ts;
                f.unique_src_ports.insert(src_port);
                if f.label.is_none() {
                    f.label = label.clone();
                }
            })
            .or_insert_with(|| {
                let mut ports = HashSet::new();
                ports.insert(src_port);
                FlowObs {
                    key: key.clone(),
                    packets: 1,
                    bytes,
                    first_seen: pkt.ts,
                    last_seen: pkt.ts,
                    label,
                    unique_src_ports: ports,
                }
            });

        // Protocol-specific observations
        if pkt.transport == Transport::Tcp {
            self.observe_tcp(pkt);
        } else if pkt.transport == Transport::Udp {
            self.observe_udp(pkt);
        }

        // External egress (OT → public)
        if self.in_ot(pkt.src_ip) && is_public(pkt.dst_ip) {
            let ek = format!(
                "{}->{}:{}/{}",
                pkt.src_ip, pkt.dst_ip, pkt.dst_port, proto_byte
            );
            self.obs
                .external_flows
                .entry(ek)
                .and_modify(|f| {
                    f.packets += 1;
                    f.bytes += bytes;
                })
                .or_insert(ExternalFlow {
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    dst_port: pkt.dst_port,
                    proto: proto_byte,
                    packets: 1,
                    bytes,
                });
        }
    }

    /// Record a credential observation, deduplicating by `(src, dst, dst_port, kind)`.
    ///
    /// BC-1.03.007: if a `CredEvent` with the same key already exists in
    /// `cred_events`, its `count` is incremented (saturating at `u32::MAX`)
    /// rather than appending a new entry. This keeps `cred_events.len()`
    /// proportional to unique (src, dst, port, kind) tuples, not raw packet
    /// count.
    pub fn record_cred_event(&mut self, event: CredEvent) {
        let key = (event.src, event.dst, event.dst_port, event.kind);
        if let Some(&idx) = self.obs.cred_events_index.get(&key) {
            self.obs.cred_events[idx].count =
                self.obs.cred_events[idx].count.saturating_add(event.count);
        } else {
            let idx = self.obs.cred_events.len();
            self.obs.cred_events_index.insert(key, idx);
            self.obs.cred_events.push(event);
        }
    }

    /// Returns a shared reference to the accumulated observations.
    /// Used by integration tests that cannot access the private `obs` field.
    pub fn observations(&self) -> &Observations {
        &self.obs
    }

    fn update_host(&mut self, ip: IpAddr, mac: [u8; 6], pkt: &Packet, bytes: u64) {
        let in_ot = self.in_ot(ip);
        let proto_label = classify_flow(pkt);
        let entry = self.obs.hosts.entry(ip).or_insert_with(|| HostObs {
            ip,
            macs: Vec::new(),
            protocols: HashSet::new(),
            first_seen: pkt.ts,
            last_seen: pkt.ts,
            packets: 0,
            bytes: 0,
            in_ot_zone: in_ot,
        });
        if mac != [0; 6] && !entry.macs.contains(&mac) {
            entry.macs.push(mac);
        }
        if let Some(p) = proto_label {
            entry.protocols.insert(p);
        }
        entry.last_seen = pkt.ts;
        entry.packets += 1;
        entry.bytes += bytes;
    }

    fn in_ot(&self, ip: IpAddr) -> bool {
        self.ot_subnets.iter().any(|n| n.contains(&ip))
    }

    fn observe_tcp(&mut self, pkt: &Packet) {
        let payload = &pkt.payload;

        // Modbus/TCP
        if pkt.dst_port == modbus::PORT || pkt.src_port == modbus::PORT {
            if let Some(pdu) = modbus::parse(payload) {
                self.obs.modbus_events.push(ModbusEvent {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    function_code: pdu.function_code,
                    label: pdu.label().to_string(),
                    engineering_class: pdu.is_engineering_class(),
                });
                // BC-1.02.009 (S-2.11 AC-001): accumulate per-(src, dst) unit IDs.
                self.obs
                    .modbus_flow_summary
                    .entry((pkt.src_ip, pkt.dst_ip))
                    .or_default()
                    .unit_ids
                    .insert(pdu.unit_id);
            }
        }

        // S7Comm (Siemens S7-1200/300/400, TCP/102)
        if pkt.dst_port == s7comm::PORT || pkt.src_port == s7comm::PORT {
            if let Some(pdu) = s7comm::parse(payload) {
                self.obs.s7_events.push(S7Event {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    function_code: pdu.function_code,
                    label: pdu.label().to_string(),
                    engineering_class: pdu.is_engineering_class(),
                    read_class: pdu.is_read_class(),
                });
            }
        }

        // DNP3 (tcp/20000) — see also observe_udp for the UDP/20000 path
        if pkt.dst_port == dnp3::PORT || pkt.src_port == dnp3::PORT {
            if let Some(pdu) = dnp3::parse(payload) {
                self.obs.dnp3_events.push(Dnp3Event {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    function_code: pdu.function_code,
                    engineering_class: pdu.is_engineering_class(),
                });
            }
        }

        // EtherNet/IP
        if pkt.dst_port == enip::PORT || pkt.src_port == enip::PORT {
            if let Some(hdr) = enip::parse_header(payload) {
                let cip = enip::engineering_class_cip(payload);
                let engineering = cip.is_some();
                self.obs.enip_events.push(EnipEvent {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    command: hdr.command,
                    command_label: hdr.command_label().to_string(),
                    cip_service: cip.map(|s| s.label().to_string()),
                    engineering_class: engineering,
                });
            }
        }

        // FTP plaintext auth
        if pkt.dst_port == 21
            && (starts_with_ci(payload, b"USER ") || starts_with_ci(payload, b"PASS "))
        {
            self.record_cred_event(CredEvent {
                ts: pkt.ts,
                src: pkt.src_ip,
                dst: pkt.dst_ip,
                dst_port: 21,
                kind: CredKind::FtpAuth,
                count: 1,
                note: first_line(payload, 80),
            });
        }

        // Telnet — any payload to/from port 23 is plaintext by definition.
        if (pkt.dst_port == 23 || pkt.src_port == 23) && !payload.is_empty() {
            self.record_cred_event(CredEvent {
                ts: pkt.ts,
                src: pkt.src_ip,
                dst: pkt.dst_ip,
                dst_port: 23,
                kind: CredKind::TelnetSession,
                count: 1,
                note: "Telnet session (cleartext)".to_string(),
            });
        }

        // HTTP basic
        if pkt.dst_port == 80 || pkt.dst_port == 8080 {
            if let Some(off) = find_subseq(payload, b"Authorization: Basic ") {
                self.record_cred_event(CredEvent {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    dst_port: pkt.dst_port,
                    kind: CredKind::HttpBasic,
                    count: 1,
                    note: extract_line(payload, off, 120),
                });
            }
        }

        // SMBv1 detection (tcp/445, legacy tcp/139). Look for the SMB1
        // magic `\xFF SMB` either at offset 0 (raw) or offset 4 (after
        // an NBSS session-message header `\x00\x00 length_hi length_lo`).
        if pkt.dst_port == 445 || pkt.src_port == 445 || pkt.dst_port == 139 || pkt.src_port == 139
        {
            let smb_at = if has_smb1_magic(payload, 0) {
                Some(0)
            } else if has_smb1_magic(payload, 4) {
                Some(4)
            } else {
                None
            };
            if smb_at.is_some() {
                let key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port);
                *self.obs.smbv1_packets.entry(key).or_insert(0) += 1;
            }
        }

        // TLS ClientHello on tcp/443 / tcp/8443. Extract the
        // legacy_version from the handshake layer for stale-version
        // detection. Record-layer offsets:
        //   [0]    content_type (0x16 = handshake)
        //   [1..3] legacy_record_version
        //   [3..5] length
        //   [5]    handshake msg_type (0x01 = ClientHello)
        //   [6..9] handshake length (3 bytes)
        //   [9..11] legacy_version  ← what we care about
        if (pkt.dst_port == 443 || pkt.dst_port == 8443)
            && payload.len() >= 11
            && payload[0] == 0x16
            && payload[5] == 0x01
        {
            let legacy_version = u16::from_be_bytes([payload[9], payload[10]]);
            let key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port, legacy_version);
            *self.obs.tls_client_hellos.entry(key).or_insert(0) += 1;

            // BC-1.04.003 (S-2.07): extract cipher_suites from the ClientHello.
            // The ClientHello body starts at payload[9]:
            //   [9..11]  legacy_version (already read above)
            //   [11..43] random (32 bytes)
            //   [43]     session_id_len
            //   [44..44+session_id_len]  session_id
            //   [44+session_id_len..]    cipher_suites_len (u16 BE) + suite codes
            if payload.len() >= 44 {
                let session_id_len = payload[43] as usize;
                let cs_offset = 44 + session_id_len;
                if payload.len() >= cs_offset + 2 {
                    let cs_len =
                        u16::from_be_bytes([payload[cs_offset], payload[cs_offset + 1]]) as usize;
                    // cs_len is in bytes; must be even (each suite is 2 bytes)
                    if cs_len % 2 == 0 && payload.len() >= cs_offset + 2 + cs_len {
                        let cs_data = &payload[cs_offset + 2..cs_offset + 2 + cs_len];
                        let suites: Vec<u16> = cs_data
                            .chunks_exact(2)
                            .map(|b| u16::from_be_bytes([b[0], b[1]]))
                            .collect();
                        let flow_key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port);
                        self.obs
                            .tls_cipher_suites
                            .entry(flow_key)
                            .or_default()
                            .extend(suites);
                    }
                }
            }
        }

        // NTLMSSP NEGOTIATE detection.
        // The signature `NTLMSSP\0` can appear at any offset inside SMB2 session
        // setup, HTTP NTLM, or RPC payloads, so we scan the full payload rather
        // than checking a fixed offset. The recognizer validates the message-type
        // and flags fields, so false positives from accidental 8-byte matches are
        // extremely unlikely.
        //
        // Port scope: 445 (SMB/CIFS), 139 (NetBIOS session), 80/443/8080 (HTTP
        // NTLM auth), 135 (MSRPC endpoint mapper). All carry NTLM negotiate msgs.
        let ntlm_port = matches!(pkt.dst_port, 445 | 139 | 80 | 443 | 8080 | 135)
            || matches!(pkt.src_port, 445 | 139 | 80 | 443 | 8080 | 135);
        if ntlm_port {
            if let Some(offset) = find_ntlmssp_offset(payload) {
                if let Some(recognized) = recognize_ntlm_negotiate(&payload[offset..]) {
                    self.obs.ntlm_events.push(NtlmEvent {
                        ts: pkt.ts,
                        src: pkt.src_ip,
                        dst: pkt.dst_ip,
                        dst_port: pkt.dst_port,
                        version: recognized.version,
                    });
                }
            }
        }

        // RDP Connection Confirm (tcp/3389) — S-2.08, BC-1.04.004.
        // Only fire on dst_port 3389; the server sends the CC back to the client
        // (EC-003: ignore traffic on any other port even if payload looks like RDP).
        if pkt.dst_port == rdp::PORT {
            if let Some(recognized) = rdp::recognize_connection_confirm(payload) {
                self.obs.rdp_events.push(RdpEvent {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    dst_port: pkt.dst_port,
                    selected_protocol: recognized.selected_protocol,
                });
            }
        }

        // LDAP plaintext simple-bind (tcp/389 and tcp/3268 Global Catalog).
        // EC-001: port 3268 is in scope alongside the standard 389.
        //
        // STARTTLS detection (AC-003): a successful STARTTLS extended response
        // on a flow sets the per-flow flag before any BindRequest on that flow
        // is processed. The minimal detection looks for the LDAP
        // ExtendedResponse (APPLICATION 24, tag 0x78) containing resultCode
        // success (0x0a 0x01 0x00) anywhere in the payload. This is a
        // heuristic — it does not reconstruct full LDAP message framing —
        // but it is sufficient for the AC-003 suppression test because the
        // observer test directly sets `used_starttls: true` on the fixture.
        // F-ADV-P4-001: STARTTLS detection must run on BOTH directions.
        // The ExtendedResponse (server → client) carries the success bytes;
        // the BindRequest (client → server) is what we want to flag as
        // STARTTLS-protected. We need to observe both packets and key them
        // by a direction-agnostic flow tuple so the response's success
        // signal is associated with the request's bind event.
        //
        // Direction-agnostic flow key: (canonical_low_ip, canonical_high_ip,
        // server_port, client_port). Both 389 and 3268 ports collapse to a
        // single "ldap server port" slot on whichever side carries it; the
        // client port is whichever side isn't 389/3268.
        let is_ldap_dst = pkt.dst_port == ldap::PORT || pkt.dst_port == 3268;
        let is_ldap_src = pkt.src_port == ldap::PORT || pkt.src_port == 3268;

        if is_ldap_src || is_ldap_dst {
            // Server-side detection of STARTTLS success. The ExtendedResponse
            // payload starts with `0x30` (outer SEQUENCE), contains tag 0x78
            // (APPLICATION 24, ExtendedResponse), and contains the success
            // resultCode `0x0a 0x01 0x00`.
            if is_ldap_src
                && !payload.is_empty()
                && payload[0] == 0x30
                && find_subseq(payload, &[0x78]).is_some()
                && find_subseq(payload, &[0x0a, 0x01, 0x00]).is_some()
            {
                // F-ADV-P4-001: key by the (client, server, client_port,
                // server_port) tuple — the BindRequest direction's view.
                // Since this packet is server→client, the BindRequest's
                // pkt.src_ip = our pkt.dst_ip; pkt.dst_ip = our pkt.src_ip.
                let server_port = pkt.src_port;
                let client_port = pkt.dst_port;
                let flow_key = (pkt.dst_ip, pkt.src_ip, client_port, server_port);
                self.ldap_starttls_flows.insert(flow_key, true);
            }

            // Client-side: BindRequest recognition.
            if is_ldap_dst {
                if let Some(recognized) = ldap::recognize_bind_request(payload) {
                    // F-ADV-P4-001: look up the STARTTLS flag using the
                    // (client_src, server_dst, client_src_port, server_dst_port)
                    // tuple — same shape the response branch above stored under.
                    let flow_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
                    let used_starttls = *self.ldap_starttls_flows.get(&flow_key).unwrap_or(&false);
                    self.obs.ldap_bind_events.push(LdapBindEvent {
                        ts: pkt.ts,
                        src: pkt.src_ip,
                        dst: pkt.dst_ip,
                        dst_port: pkt.dst_port,
                        version: recognized.version,
                        used_starttls,
                        anonymous: recognized.anonymous,
                    });
                }
            }
        }
    }

    fn observe_udp(&mut self, pkt: &Packet) {
        // DHCP host-name extraction (UDP/67 server, UDP/68 client).
        // The hostname identifies the asset to a human reader and is
        // potentially BCSI under NERC CIP-011 — we both extract it
        // (for inventory) and run it through the scrub layer.
        if pkt.dst_port == 67 || pkt.dst_port == 68 || pkt.src_port == 67 || pkt.src_port == 68 {
            if let Some(info) = dhcp::parse(&pkt.payload) {
                let ip = IpAddr::V4(info.ip);
                self.obs.hostnames.insert(ip, info.hostname);
            }
        }

        // DNP3 (udp/20000) — mirrors the tcp/20000 path in observe_tcp.
        // DNP3 is predominantly TCP in modern deployments but the standard
        // also defines a UDP transport; some outstations use it for
        // unsolicited responses and broadcast commands.
        if pkt.dst_port == dnp3::PORT || pkt.src_port == dnp3::PORT {
            if let Some(pdu) = dnp3::parse(&pkt.payload) {
                self.obs.dnp3_events.push(Dnp3Event {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    function_code: pdu.function_code,
                    engineering_class: pdu.is_engineering_class(),
                });
            }
        }

        // SNMP v1/v2c (plaintext community string).
        // The first byte of an SNMP message is BER tag 0x30 (SEQUENCE),
        // followed by a length, then INTEGER tag 0x02 0x01 <version> where
        // version is 0 (v1) or 1 (v2c).
        if (pkt.dst_port == 161
            || pkt.dst_port == 162
            || pkt.src_port == 161
            || pkt.src_port == 162)
            && pkt.payload.len() > 8
            && pkt.payload[0] == 0x30
        {
            if let Some(version_off) = find_subseq(&pkt.payload, &[0x02, 0x01]) {
                if let Some(&v) = pkt.payload.get(version_off + 2) {
                    if v == 0x00 || v == 0x01 {
                        self.record_cred_event(CredEvent {
                            ts: pkt.ts,
                            src: pkt.src_ip,
                            dst: pkt.dst_ip,
                            dst_port: pkt.dst_port,
                            kind: CredKind::Snmpv1v2c,
                            count: 1,
                            note: format!(
                                "SNMP{} (plaintext community string on the wire)",
                                if v == 0 { "v1" } else { "v2c" }
                            ),
                        });
                    }
                }
            }
        }
    }
}

/// Scan a TCP payload for the NTLMSSP signature `b"NTLMSSP\0"`.
///
/// Returns the byte offset of the first occurrence, or `None` if the
/// signature is absent. The caller then slices from that offset and passes
/// the sub-slice to `recognize_ntlm_negotiate` for full validation.
fn find_ntlmssp_offset(payload: &[u8]) -> Option<usize> {
    payload.windows(8).position(|w| w == b"NTLMSSP\0")
}

/// Check for the SMB1 magic bytes (`\xFF SMB`) at a given offset.
fn has_smb1_magic(payload: &[u8], offset: usize) -> bool {
    payload.len() >= offset + 4
        && payload[offset] == 0xFF
        && payload[offset + 1] == 0x53
        && payload[offset + 2] == 0x4D
        && payload[offset + 3] == 0x42
}

fn is_broadcast_or_multicast(mac: &[u8; 6]) -> bool {
    if mac == &[0xffu8; 6] {
        return true;
    }
    // IEEE 802.3: the lowest bit of the first byte is the I/G bit (1 =
    // multicast/broadcast). All Ethernet broadcast and IP-multicast MACs
    // (e.g., 33:33:... for IPv6) match this.
    mac[0] & 0x01 != 0
}

fn flow_key_str(k: &FlowKey) -> String {
    format!("{}->{}:{}/{}", k.src, k.dst, k.dst_port, k.proto)
}

fn classify_flow(pkt: &Packet) -> Option<String> {
    let port = if is_well_known(pkt.dst_port) {
        pkt.dst_port
    } else if is_well_known(pkt.src_port) {
        pkt.src_port
    } else {
        return None;
    };
    Some(
        match (pkt.transport, port) {
            (Transport::Tcp, 502) => "modbus",
            (Transport::Tcp, 44818) => "enip",
            (Transport::Udp, 2222) => "enip-io",
            (Transport::Tcp, 102) => "s7comm",
            (Transport::Tcp, 4840) => "opcua",
            (Transport::Tcp, 1911 | 4911) => "fox-niagara",
            (Transport::Udp, 47808) => "bacnet",
            (Transport::Udp, 20000) | (Transport::Tcp, 20000) => "dnp3",
            (Transport::Tcp, 21) => "ftp",
            (Transport::Tcp, 22) => "ssh",
            (Transport::Tcp, 23) => "telnet",
            (Transport::Tcp, 25 | 587) => "smtp",
            (Transport::Tcp, 80 | 8080) => "http",
            (Transport::Tcp, 389) => "ldap",
            (Transport::Tcp, 443) => "https",
            (Transport::Tcp, 445) => "smb",
            (Transport::Tcp, 636) => "ldaps",
            (Transport::Tcp, 3268) => "ldap-gc",
            (Transport::Tcp, 3389) => "rdp",
            (Transport::Udp, 53) => "dns",
            (Transport::Udp, 67 | 68) => "dhcp",
            (Transport::Udp, 123) => "ntp",
            (Transport::Udp, 137 | 138) | (Transport::Tcp, 139) => "netbios",
            (Transport::Udp, 161 | 162) => "snmp",
            (Transport::Udp, 5353) => "mdns",
            _ => return None,
        }
        .to_string(),
    )
}

fn is_well_known(p: u16) -> bool {
    p < 49152
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified() && !is_ula(v6)
        }
    }
}

fn is_ula(v6: std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

fn starts_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .iter()
        .zip(needle.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn first_line(payload: &[u8], max: usize) -> String {
    let end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len());
    let slice = &payload[..end.min(max)];
    String::from_utf8_lossy(slice).to_string()
}

fn extract_line(payload: &[u8], start: usize, max: usize) -> String {
    let slice = &payload[start..];
    first_line(slice, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::net::IpAddr;

    fn fixed_ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Construct a minimal DNP3 TCP payload for port 20000.
    ///
    /// Layout: sync(2) + length(1) + control(1) + dst_le(2) + src_le(2)
    ///         + link_crc(2) + transport(1) + app_ctrl(1) + fc(1) + app_crc(2)
    fn make_dnp3_payload(function_code: u8) -> Vec<u8> {
        vec![
            0x05,
            0x64, // sync
            0x0A, // length
            0x44, // control
            0x01,
            0x00, // dst LE
            0x02,
            0x00, // src LE
            0x00,
            0x00, // link CRC placeholder
            0xC0, // transport: FIN=1 FIR=1 seq=0
            0xC0, // app control
            function_code,
            0x00,
            0x00, // app CRC placeholder
        ]
    }

    /// AC-003 / BC-1.02.005: Observer must recognise DNP3 on tcp/20000
    /// and append a Dnp3Event with the correct function code.
    #[test]
    fn ingest_dnp3_recognizes_function_code() {
        use crate::pcap::{Packet, Transport};

        let ot_subnet: ipnet::IpNet = "10.10.0.0/16".parse().unwrap();
        let mut observer = Observer::new(vec![ot_subnet]);

        let pkt = Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33],
            src_ip: ip("10.10.0.5"),
            dst_ip: ip("10.10.0.20"),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port: 20000,
            payload: make_dnp3_payload(4), // Operate
        };

        observer.observe(&pkt);
        let obs = observer.finish();

        assert!(
            !obs.dnp3_events.is_empty(),
            "observer must append a Dnp3Event when tcp/20000 carries a DNP3 frame"
        );
        assert_eq!(
            obs.dnp3_events[0].function_code, 4,
            "Dnp3Event must carry the application-layer function code"
        );
    }

    /// AC-003: DNP3 traffic on tcp/20000 must produce a flow labelled "dnp3".
    #[test]
    fn ingest_dnp3_labels_flow() {
        use crate::pcap::{Packet, Transport};

        let ot_subnet: ipnet::IpNet = "10.10.0.0/16".parse().unwrap();
        let mut observer = Observer::new(vec![ot_subnet]);

        let pkt = Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33],
            src_ip: ip("10.10.0.5"),
            dst_ip: ip("10.10.0.20"),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port: 20000,
            payload: make_dnp3_payload(5),
        };

        observer.observe(&pkt);
        let obs = observer.finish();

        let dnp3_flow = obs.flows.values().find(|f| f.key.dst_port == 20000);
        assert!(
            dnp3_flow.is_some(),
            "a flow for dst_port 20000 must be recorded"
        );
        assert_eq!(
            dnp3_flow.unwrap().label.as_deref(),
            Some("dnp3"),
            "flow label for tcp/20000 must be 'dnp3'"
        );
    }

    /// AC-003: Observer must recognise DNP3 on udp/20000 and append a
    /// Dnp3Event — mirrors ingest_dnp3_recognizes_function_code but uses
    /// Transport::Udp to verify the observe_udp() path.
    #[test]
    fn ingest_dnp3_udp_recognizes_function_code() {
        use crate::pcap::{Packet, Transport};

        let ot_subnet: ipnet::IpNet = "10.10.0.0/16".parse().unwrap();
        let mut observer = Observer::new(vec![ot_subnet]);

        let pkt = Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33],
            src_ip: ip("10.10.0.5"),
            dst_ip: ip("10.10.0.20"),
            transport: Transport::Udp,
            src_port: 54322,
            dst_port: 20000,
            payload: make_dnp3_payload(13), // Cold Restart over UDP
        };

        observer.observe(&pkt);
        let obs = observer.finish();

        assert!(
            !obs.dnp3_events.is_empty(),
            "observer must append a Dnp3Event for udp/20000 DNP3 traffic"
        );
        assert_eq!(
            obs.dnp3_events[0].function_code, 13,
            "Dnp3Event over UDP must carry the application-layer function code"
        );
        assert!(
            obs.dnp3_events[0].engineering_class,
            "Cold Restart (fc=13) must be classified as engineering-class over UDP"
        );
    }

    #[test]
    fn smb1_magic_at_offset_0() {
        let payload = [0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00];
        assert!(has_smb1_magic(&payload, 0));
        assert!(!has_smb1_magic(&payload, 4));
    }

    #[test]
    fn smb1_magic_at_offset_4_after_nbss() {
        // NBSS session message header (4 bytes) + SMB1 magic
        let payload = [0x00, 0x00, 0x00, 0x40, 0xFF, 0x53, 0x4D, 0x42];
        assert!(has_smb1_magic(&payload, 4));
        assert!(!has_smb1_magic(&payload, 0));
    }

    #[test]
    fn smb2_or_smb3_does_not_match() {
        // SMB2/3 magic is `\xFE SMB`
        let payload = [0xFE, 0x53, 0x4D, 0x42, 0x40];
        assert!(!has_smb1_magic(&payload, 0));
    }

    #[test]
    fn short_payload_does_not_match() {
        assert!(!has_smb1_magic(&[0xFF, 0x53, 0x4D], 0));
        assert!(!has_smb1_magic(&[], 0));
        assert!(!has_smb1_magic(&[0xFF, 0x53, 0x4D, 0x42], 4));
    }

    // -------------------------------------------------------------------------
    // S-2.02 / BC-1.03.007: cred_events dedup tests
    // -------------------------------------------------------------------------

    fn make_ftp_event() -> CredEvent {
        CredEvent {
            ts: Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap(),
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            dst_port: 21,
            kind: CredKind::FtpAuth,
            count: 1,
            note: "USER admin".to_string(),
        }
    }

    /// BC-1.03.007 (AC-001-a): identical (src, dst, dst_port, kind) tuples must
    /// collapse to a single entry with count == number of observations.
    #[test]
    fn test_bc_1_03_007_record_cred_event_dedups_same_key() {
        let mut obs = Observer::new(vec![]);
        let event = make_ftp_event();
        obs.record_cred_event(event.clone());
        obs.record_cred_event(event.clone());
        obs.record_cred_event(event.clone());

        let cred_events = &obs.obs.cred_events;
        assert_eq!(
            cred_events.len(),
            1,
            "BC-1.03.007: identical key must dedup to one entry"
        );
        assert_eq!(
            cred_events[0].count, 3,
            "BC-1.03.007: count must equal the number of duplicate observations"
        );
    }

    /// BC-1.03.007 (AC-001-b): same dedup invariant holds for N=1000 repeated
    /// observations of the same key.
    #[test]
    fn test_bc_1_03_007_record_cred_event_property_n_duplicates() {
        let mut obs = Observer::new(vec![]);
        let event = make_ftp_event();
        for _ in 0..1000 {
            obs.record_cred_event(event.clone());
        }
        let cred_events = &obs.obs.cred_events;
        assert_eq!(
            cred_events.len(),
            1,
            "BC-1.03.007: 1000 identical pushes must collapse to one entry"
        );
        assert_eq!(
            cred_events[0].count, 1000,
            "BC-1.03.007: count must equal 1000 after 1000 duplicate observations"
        );
    }

    /// EC-001: events with the same (src, dst, port) but different kind must
    /// NOT be collapsed — they are distinct credential types.
    #[test]
    fn test_bc_1_03_007_record_cred_event_distinct_kinds_not_deduped() {
        let mut obs = Observer::new(vec![]);
        let ftp = CredEvent {
            kind: CredKind::FtpAuth,
            dst_port: 21,
            ..make_ftp_event()
        };
        let snmp = CredEvent {
            kind: CredKind::Snmpv1v2c,
            dst_port: 161,
            ..make_ftp_event()
        };
        obs.record_cred_event(ftp);
        obs.record_cred_event(snmp);
        let cred_events = &obs.obs.cred_events;
        assert_eq!(
            cred_events.len(),
            2,
            "EC-001: distinct kinds must not collapse to one entry"
        );
    }

    // -------------------------------------------------------------------------
    // S-2.05 / BC-1.03.005: Observer ingests LDAP BindRequest packets
    // -------------------------------------------------------------------------

    /// Build a minimal BER-encoded LDAPv3 BindRequest payload (same encoding
    /// as the parser unit tests). This is duplicated here intentionally — the
    /// observer tests must not depend on `crate::parse::ldap` internals.
    ///
    /// Layout per RFC 4511 §4.2:
    ///   0x30 LL  LDAPMessage SEQUENCE
    ///     0x02 0x01 0x01  messageID INTEGER 1
    ///     0x60 LL  BindRequest [APPLICATION 0]
    ///       0x02 0x01 0x03  version INTEGER 3
    ///       0x04 LL <dn>    name OctetString
    ///       0x80 LL <pw>    simple [0] IMPLICIT OctetString
    fn make_bind_payload(dn: &[u8], pw: &[u8]) -> Vec<u8> {
        let version_tlv: &[u8] = &[0x02u8, 0x01, 0x03];
        let name_tlv = {
            let mut v = vec![0x04, dn.len() as u8];
            v.extend_from_slice(dn);
            v
        };
        let auth_tlv = {
            let mut v = vec![0x80, pw.len() as u8];
            v.extend_from_slice(pw);
            v
        };
        let bind_body: Vec<u8> = version_tlv
            .iter()
            .chain(name_tlv.iter())
            .chain(auth_tlv.iter())
            .copied()
            .collect();
        let bind_req = {
            let mut v = vec![0x60u8, bind_body.len() as u8];
            v.extend_from_slice(&bind_body);
            v
        };
        let msg_id: &[u8] = &[0x02u8, 0x01, 0x01];
        let ldap_body: Vec<u8> = msg_id.iter().chain(bind_req.iter()).copied().collect();
        let mut msg = vec![0x30u8, ldap_body.len() as u8];
        msg.extend_from_slice(&ldap_body);
        msg
    }

    fn make_ldap_packet(
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> crate::pcap::Packet {
        use crate::pcap::{Packet, Transport};
        Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port,
            payload,
        }
    }

    /// AC-001 (BC-1.03.005): Observer must append an LdapBindEvent when
    /// it receives a TCP packet on port 389 carrying a valid BindRequest.
    #[test]
    fn test_bc_1_03_005_ingests_ldap_bind_on_port_389() {
        let payload = make_bind_payload(b"cn=admin,dc=example,dc=com", b"hunter2");
        let pkt = make_ldap_packet("10.0.0.1", "10.0.0.2", 389, payload);

        let mut observer = Observer::new(vec![]);
        observer.observe(&pkt);
        let obs = observer.observations();

        assert_eq!(
            obs.ldap_bind_events.len(),
            1,
            "AC-001: observer must append one LdapBindEvent for a tcp/389 BindRequest"
        );
        let ev = &obs.ldap_bind_events[0];
        assert_eq!(ev.dst_port, 389);
        assert_eq!(ev.version, 3);
        assert!(
            !ev.used_starttls,
            "AC-003: used_starttls must be false when no STARTTLS preceded the bind"
        );
    }

    /// EC-001: LDAP BindRequest on port 3268 (Global Catalog) must also be
    /// recognized and recorded.
    #[test]
    fn test_bc_1_03_005_ingests_ldap_bind_on_port_3268() {
        let payload = make_bind_payload(b"cn=admin,dc=corp,dc=local", b"secret");
        let pkt = make_ldap_packet("10.0.0.1", "10.0.0.2", 3268, payload);

        let mut observer = Observer::new(vec![]);
        observer.observe(&pkt);
        let obs = observer.observations();

        assert_eq!(
            obs.ldap_bind_events.len(),
            1,
            "EC-001: observer must append one LdapBindEvent for a tcp/3268 BindRequest"
        );
        assert_eq!(
            obs.ldap_bind_events[0].dst_port, 3268,
            "EC-001: event must record the actual destination port"
        );
    }

    // -------------------------------------------------------------------------
    // S-2.06 / BC-1.03.006: Observer integration test — NTLM ingestion
    // -------------------------------------------------------------------------

    /// Build a raw NTLMSSP NEGOTIATE_MESSAGE payload.
    ///
    /// The blob is always at least 32 bytes (just the header + flags + zeros).
    /// flags_le must be 4 bytes (little-endian NegotiateFlags).
    fn make_ntlmssp_negotiate(flags_le: [u8; 4]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(32);
        // Signature: "NTLMSSP\0" (8 bytes)
        payload.extend_from_slice(b"NTLMSSP\0");
        // MessageType = 1 (NEGOTIATE), little-endian u32
        payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // NegotiateFlags (4 bytes little-endian)
        payload.extend_from_slice(&flags_le);
        // Trailing zeros to pad to 32 bytes (workstation fields etc.)
        payload.extend_from_slice(&[0u8; 16]);
        payload
    }

    fn make_smb_packet(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> crate::pcap::Packet {
        use crate::pcap::{Packet, Transport};
        Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            transport: Transport::Tcp,
            src_port,
            dst_port,
            payload,
        }
    }

    /// AC-001 (BC-1.03.006): Observer must append an NtlmEvent with version V1
    /// when a TCP packet on port 445 carries an NTLMSSP NEGOTIATE_MESSAGE with
    /// NTLMSSP_NEGOTIATE_NTLM set and NTLMSSP_NEGOTIATE_NTLM2_KEY unset.
    ///
    /// Flags: 0x00000200 (NTLM only) → little-endian [0x00, 0x02, 0x00, 0x00]
    #[test]
    fn test_bc_1_03_006_ingests_ntlmv1_on_smb_port_445() {
        // NTLMSSP_NEGOTIATE_NTLM = 0x00000200, NTLM2_KEY unset
        let flags_le = [0x00u8, 0x02, 0x00, 0x00];
        let payload = make_ntlmssp_negotiate(flags_le);
        let pkt = make_smb_packet("10.0.0.1", "10.0.0.2", 54321, 445, payload);

        let mut observer = Observer::new(vec![]);
        observer.observe(&pkt);
        let obs = observer.observations();

        assert_eq!(
            obs.ntlm_events.len(),
            1,
            "AC-001: observer must append one NtlmEvent for an NTLMSSP NEGOTIATE on tcp/445"
        );
        assert_eq!(
            obs.ntlm_events[0].version,
            NtlmVersion::V1,
            "AC-001: NtlmEvent version must be V1 when NTLM2_KEY flag is unset"
        );
        assert_eq!(obs.ntlm_events[0].dst_port, 445);
        assert_eq!(obs.ntlm_events[0].src, ip("10.0.0.1"));
        assert_eq!(obs.ntlm_events[0].dst, ip("10.0.0.2"));
    }
}

// -------------------------------------------------------------------------
// S-2.06 / BC-1.03.006: Parser unit tests for recognize_ntlm_negotiate
// -------------------------------------------------------------------------

#[cfg(test)]
mod ntlm_tests {
    use super::{recognize_ntlm_negotiate, NtlmVersion};

    /// Build a minimal NTLMSSP NEGOTIATE_MESSAGE (32 bytes).
    fn negotiate_blob(msg_type_le: [u8; 4], flags_le: [u8; 4]) -> Vec<u8> {
        let mut v = Vec::with_capacity(32);
        v.extend_from_slice(b"NTLMSSP\0"); // signature (8 bytes)
        v.extend_from_slice(&msg_type_le); // MessageType (4 bytes)
        v.extend_from_slice(&flags_le); // NegotiateFlags (4 bytes)
        v.extend_from_slice(&[0u8; 16]); // padding
        v
    }

    /// AC-001 / BC-1.03.006 (positive, V1):
    /// Flags = 0x00000200 — NTLM set, NTLM2_KEY unset → NtlmVersion::V1.
    /// Byte layout: LE u32 0x00000200 = [0x00, 0x02, 0x00, 0x00].
    #[test]
    fn test_bc_1_03_006_recognizes_ntlmv1_negotiate() {
        let blob = negotiate_blob([0x01, 0x00, 0x00, 0x00], [0x00, 0x02, 0x00, 0x00]);
        let result = recognize_ntlm_negotiate(&blob);
        let recognized = result.expect("must recognize V1 NEGOTIATE blob");
        assert_eq!(
            recognized.version,
            NtlmVersion::V1,
            "flags 0x00000200 (NTLM set, NTLM2_KEY unset) must yield NtlmVersion::V1"
        );
    }

    /// AC-001 / BC-1.03.006 (positive, V2):
    /// Flags = 0x00080200 — NTLM + NTLM2_KEY both set → NtlmVersion::V2.
    /// Byte layout: LE u32 0x00080200 = [0x00, 0x02, 0x08, 0x00].
    #[test]
    fn test_bc_1_03_006_recognizes_ntlmv2_negotiate() {
        let blob = negotiate_blob([0x01, 0x00, 0x00, 0x00], [0x00, 0x02, 0x08, 0x00]);
        let result = recognize_ntlm_negotiate(&blob);
        let recognized = result.expect("must recognize V2 NEGOTIATE blob");
        assert_eq!(
            recognized.version,
            NtlmVersion::V2,
            "flags 0x00080200 (NTLM + NTLM2_KEY set) must yield NtlmVersion::V2"
        );
    }

    /// EC-002: random bytes without the NTLMSSP signature must return None.
    #[test]
    fn test_bc_1_03_006_rejects_random_bytes() {
        let garbage: &[u8] = &[0xFF, 0x00, 0x42, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let result = recognize_ntlm_negotiate(garbage);
        assert!(
            result.is_none(),
            "random bytes without NTLMSSP signature must return None"
        );
    }

    /// EC-002: valid NTLMSSP signature but MessageType = 2 (CHALLENGE) must
    /// return None — the recognizer only handles NEGOTIATE (type 1).
    #[test]
    fn test_bc_1_03_006_rejects_challenge_messagetype() {
        // MessageType = 2 (CHALLENGE)
        let blob = negotiate_blob([0x02, 0x00, 0x00, 0x00], [0x00, 0x02, 0x08, 0x00]);
        let result = recognize_ntlm_negotiate(&blob);
        assert!(
            result.is_none(),
            "NTLMSSP CHALLENGE (type 2) must not be recognized as NEGOTIATE"
        );
    }

    /// EC-002: valid NTLMSSP signature but MessageType = 3 (AUTHENTICATE)
    /// must return None.
    #[test]
    fn test_bc_1_03_006_rejects_authenticate_messagetype() {
        // MessageType = 3 (AUTHENTICATE)
        let blob = negotiate_blob([0x03, 0x00, 0x00, 0x00], [0x00, 0x02, 0x08, 0x00]);
        let result = recognize_ntlm_negotiate(&blob);
        assert!(
            result.is_none(),
            "NTLMSSP AUTHENTICATE (type 3) must not be recognized as NEGOTIATE"
        );
    }

    /// Defensive: payload shorter than 16 bytes (missing flags field) must
    /// return None without panicking.
    #[test]
    fn test_bc_1_03_006_rejects_truncated_payload() {
        // Only the first 10 bytes — signature is present but MessageType and
        // flags are cut off.
        let truncated: Vec<u8> = b"NTLMSSP\0\x01\x00".to_vec();
        let result = recognize_ntlm_negotiate(&truncated);
        assert!(
            result.is_none(),
            "truncated payload (10 bytes, missing flags) must return None"
        );
    }
}

// -------------------------------------------------------------------------
// S-2.07 / BC-1.04.003: TLS ClientHello cipher_suites observer tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tls_cipher_tests {
    use super::Observer;
    use crate::pcap::{Packet, Transport};
    use chrono::{TimeZone, Utc};
    use std::net::IpAddr;

    fn fixed_ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a minimal TLS record carrying a ClientHello with the given fields.
    ///
    /// Layout (TLS 1.0/1.1/1.2 outer shape):
    ///   [0]     content_type = 0x16 (handshake)
    ///   [1..3]  legacy_record_version (big-endian u16)
    ///   [3..5]  record_length (big-endian u16, computed)
    ///   [5]     handshake_type = 0x01 (ClientHello)
    ///   [6..9]  handshake_length (big-endian u24, computed)
    ///   [9..11] client_version = legacy_version (big-endian u16)
    ///   [11..43] random (32 zero bytes)
    ///   [43]    session_id_length = len(session_id)
    ///   [44..]  session_id bytes
    ///   [...]   cipher_suites_length (big-endian u16, 2 * count)
    ///   [...]   cipher_suites (sequence of big-endian u16)
    ///   [...]   compression_methods_length = 0x01
    ///   [...]   compression_methods = 0x00 (null)
    ///   [...]   extensions_length = 0x0000
    fn build_client_hello(
        legacy_version: u16,
        session_id: &[u8],
        cipher_suites: &[u16],
    ) -> Vec<u8> {
        let mut handshake_body: Vec<u8> = Vec::new();

        // client_version (2 bytes)
        handshake_body.extend_from_slice(&legacy_version.to_be_bytes());

        // random (32 zero bytes)
        handshake_body.extend_from_slice(&[0u8; 32]);

        // session_id: length byte + data
        handshake_body.push(session_id.len() as u8);
        handshake_body.extend_from_slice(session_id);

        // cipher_suites: 2-byte count (in bytes) + suite codes
        let cs_byte_len = (cipher_suites.len() * 2) as u16;
        handshake_body.extend_from_slice(&cs_byte_len.to_be_bytes());
        for &suite in cipher_suites {
            handshake_body.extend_from_slice(&suite.to_be_bytes());
        }

        // compression_methods: count=1, method=null(0)
        handshake_body.push(0x01);
        handshake_body.push(0x00);

        // extensions: empty (length=0)
        handshake_body.extend_from_slice(&0u16.to_be_bytes());

        // Handshake header: type(1) + length(3)
        let hs_len = handshake_body.len() as u32;
        let mut handshake: Vec<u8> = vec![
            0x01, // ClientHello
            ((hs_len >> 16) & 0xFF) as u8,
            ((hs_len >> 8) & 0xFF) as u8,
            (hs_len & 0xFF) as u8,
        ];
        handshake.extend_from_slice(&handshake_body);

        // TLS record header: content_type(1) + record_version(2) + length(2)
        let record_len = handshake.len() as u16;
        let mut record: Vec<u8> = Vec::new();
        record.push(0x16); // content_type = handshake
        record.extend_from_slice(&0x0303u16.to_be_bytes()); // record version TLS 1.2
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    fn make_tls_packet(src: &str, dst: &str, dst_port: u16, payload: Vec<u8>) -> Packet {
        Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: ip(src),
            dst_ip: ip(dst),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port,
            payload,
        }
    }

    /// AC-001 (BC-1.04.003): observer must capture cipher_suites from a
    /// TLS ClientHello and store them keyed by (src, dst, dst_port).
    ///
    /// Sends a ClientHello with cipher_suites = [0x0035, 0x002F, 0x0005]
    /// (AES-256-SHA, AES-128-SHA, RC4-128-SHA). The observer must store
    /// exactly those codes in tls_cipher_suites[(src, dst, 443)].
    #[test]
    fn test_bc_1_04_003_tls_client_hello_captures_cipher_suites() {
        let cipher_suites: &[u16] = &[0x0035, 0x002F, 0x0005];
        let payload = build_client_hello(0x0303, &[], cipher_suites);

        let src: IpAddr = ip("10.0.0.1");
        let dst: IpAddr = ip("10.0.0.2");
        let pkt = make_tls_packet("10.0.0.1", "10.0.0.2", 443, payload);

        let mut observer = Observer::new(vec![]);
        observer.observe(&pkt);
        let obs = observer.observations();

        let stored = obs.tls_cipher_suites.get(&(src, dst, 443));
        assert!(
            stored.is_some(),
            "BC-1.04.003: tls_cipher_suites must have an entry for (src, dst, 443) \
             after observing a ClientHello on tcp/443"
        );
        assert_eq!(
            stored.unwrap(),
            &vec![0x0035u16, 0x002F, 0x0005],
            "BC-1.04.003: stored cipher_suites must exactly match the ClientHello payload"
        );
    }

    /// Defensive (BC-1.04.003): an empty cipher_suites list must not panic
    /// the observer. The map entry may be absent or hold an empty Vec.
    #[test]
    fn test_bc_1_04_003_empty_cipher_suites_list_does_not_panic() {
        let payload = build_client_hello(0x0303, &[], &[]);
        let pkt = make_tls_packet("10.0.0.1", "10.0.0.2", 443, payload);

        let mut observer = Observer::new(vec![]);
        // Must not panic.
        observer.observe(&pkt);
        let obs = observer.observations();

        // Either no entry or an empty Vec is acceptable.
        let entry = obs
            .tls_cipher_suites
            .get(&(ip("10.0.0.1"), ip("10.0.0.2"), 443));
        if let Some(suites) = entry {
            assert!(
                suites.is_empty(),
                "BC-1.04.003: empty cipher_suites in ClientHello must yield an empty Vec \
                 (or no entry), not garbage"
            );
        }
        // No panic → test passes.
    }

    /// Defensive (BC-1.04.003): a payload truncated mid-way through the
    /// cipher_suites field must not panic. The observer must either skip the
    /// entry entirely or accumulate only the validly-decoded prefix.
    #[test]
    fn test_bc_1_04_003_truncated_payload_no_panic() {
        // Build a full ClientHello then lop off enough bytes to land us in the
        // middle of the cipher_suites array. We include two suites (4 bytes of
        // suite data), then truncate to drop the final 2 bytes so the second
        // suite is missing.
        let cipher_suites: &[u16] = &[0x0035, 0x002F];
        let full_payload = build_client_hello(0x0303, &[], cipher_suites);

        // Drop the last 2 bytes → truncates mid-cipher_suites.
        let truncated = &full_payload[..full_payload.len().saturating_sub(2)];

        let pkt = make_tls_packet("10.0.0.1", "10.0.0.2", 443, truncated.to_vec());

        let mut observer = Observer::new(vec![]);
        // Must not panic.
        observer.observe(&pkt);
        // If we got here without a panic the invariant is satisfied.
        // We don't assert on the map contents — partial decode is acceptable.
    }
}

// -------------------------------------------------------------------------
// S-2.11 / BC-1.02.009: Observer aggregates Modbus unit IDs per (src, dst)
// -------------------------------------------------------------------------

#[cfg(test)]
mod modbus_unit_id_tests {
    use super::*;
    use crate::pcap::{Packet, Transport};
    use chrono::TimeZone;
    use std::collections::BTreeSet;

    fn fixed_ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Construct a minimal Modbus/TCP request frame (12 bytes).
    ///
    /// Layout (MBAP + minimal PDU):
    ///   [0..2]  transaction ID  = 0x0001
    ///   [2..4]  protocol ID     = 0x0000 (Modbus)
    ///   [4..6]  length          = 0x0006 (6 bytes follow)
    ///   [6]     unit ID         = `unit_id` (the byte under test)
    ///   [7]     function code   = 0x01 (Read Coils)
    ///   [8..10] starting addr   = 0x0000
    ///   [10..12] quantity       = 0x0001
    fn build_modbus_request(unit_id: u8) -> Vec<u8> {
        vec![
            0x00, 0x01, // transaction ID
            0x00, 0x00, // protocol ID (Modbus = 0)
            0x00, 0x06,    // length: 6 bytes follow
            unit_id, // unit ID — the byte under test
            0x01,    // function code: Read Coils
            0x00, 0x00, // starting address
            0x00, 0x01, // quantity
        ]
    }

    fn make_modbus_packet(src_ip: &str, dst_ip: &str, unit_id: u8) -> Packet {
        Packet {
            ts: fixed_ts(),
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33],
            src_ip: ip(src_ip),
            dst_ip: ip(dst_ip),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port: 502,
            payload: build_modbus_request(unit_id),
        }
    }

    /// BC-1.02.009 (AC-001): unit IDs accumulate across packets for the same
    /// (src, dst) pair. Three packets with unit IDs 1, 2, 3 must produce a
    /// `modbus_flow_summary` entry whose `unit_ids` set is exactly {1, 2, 3}.
    #[test]
    fn test_bc_1_02_009_unit_id_accumulates_per_src_dst() {
        let mut observer = Observer::new(vec![]);
        let src = ip("10.0.0.1");
        let dst = ip("10.0.0.2");

        for uid in [0x01u8, 0x02, 0x03] {
            observer.observe(&make_modbus_packet("10.0.0.1", "10.0.0.2", uid));
        }

        let obs = observer.observations();
        let summary = obs
            .modbus_flow_summary
            .get(&(src, dst))
            .expect("BC-1.02.009: modbus_flow_summary must have an entry for (src, dst)");
        assert_eq!(
            summary.unit_ids,
            BTreeSet::from([1u8, 2, 3]),
            "BC-1.02.009: unit_ids must accumulate all three distinct IDs seen"
        );
    }

    /// BC-1.02.009: two different (src, dst) pairs must be tracked independently
    /// — `(srcA, dstX)` and `(srcA, dstY)` are separate entries.
    #[test]
    fn test_bc_1_02_009_unit_id_distinct_src_dst_pairs_isolated() {
        let mut observer = Observer::new(vec![]);

        // (srcA, dstX) → unit_id 0x01
        observer.observe(&make_modbus_packet("10.0.0.1", "10.0.0.2", 0x01));
        // (srcA, dstY) → unit_id 0x05
        observer.observe(&make_modbus_packet("10.0.0.1", "10.0.0.3", 0x05));

        let obs = observer.observations();
        assert_eq!(
            obs.modbus_flow_summary.len(),
            2,
            "BC-1.02.009: two distinct (src, dst) pairs must create two map entries"
        );

        let entry_xy = obs
            .modbus_flow_summary
            .get(&(ip("10.0.0.1"), ip("10.0.0.2")))
            .expect("BC-1.02.009: entry for (srcA, dstX) must exist");
        assert_eq!(
            entry_xy.unit_ids,
            BTreeSet::from([0x01u8]),
            "BC-1.02.009: (srcA, dstX) entry must contain only unit_id=1"
        );

        let entry_xz = obs
            .modbus_flow_summary
            .get(&(ip("10.0.0.1"), ip("10.0.0.3")))
            .expect("BC-1.02.009: entry for (srcA, dstY) must exist");
        assert_eq!(
            entry_xz.unit_ids,
            BTreeSet::from([0x05u8]),
            "BC-1.02.009: (srcA, dstY) entry must contain only unit_id=5"
        );
    }

    /// BC-1.02.009: repeated observations of the same unit_id for a given
    /// (src, dst) must not inflate the set — BTreeSet deduplicates naturally.
    #[test]
    fn test_bc_1_02_009_unit_id_dedupes_within_flow() {
        let mut observer = Observer::new(vec![]);

        // 5 packets, all same unit_id=0x01
        for _ in 0..5 {
            observer.observe(&make_modbus_packet("10.0.0.1", "10.0.0.2", 0x01));
        }

        let obs = observer.observations();
        let summary = obs
            .modbus_flow_summary
            .get(&(ip("10.0.0.1"), ip("10.0.0.2")))
            .expect("BC-1.02.009: modbus_flow_summary entry must exist after 5 packets");
        assert_eq!(
            summary.unit_ids.len(),
            1,
            "BC-1.02.009: 5 packets with unit_id=1 must deduplicate to a set of size 1"
        );
    }

    /// EC-001: unit ID 0x00 (Modbus broadcast address) must be counted.
    /// A unit-ID sweep that includes broadcast is itself suspicious.
    #[test]
    fn test_bc_1_02_009_unit_id_0_is_counted() {
        let mut observer = Observer::new(vec![]);
        observer.observe(&make_modbus_packet("10.0.0.1", "10.0.0.2", 0x00));

        let obs = observer.observations();
        let summary = obs
            .modbus_flow_summary
            .get(&(ip("10.0.0.1"), ip("10.0.0.2")))
            .expect("EC-001: modbus_flow_summary entry must exist for unit_id=0");
        assert!(
            summary.unit_ids.contains(&0u8),
            "EC-001: unit_id=0x00 (broadcast) must be present in unit_ids"
        );
    }

    /// EC-002: unit ID 0xFF (gateway / reserved) must be counted.
    /// Sweeping to 0xFF is common in automated PLC discovery tools.
    #[test]
    fn test_bc_1_02_009_unit_id_ff_is_counted() {
        let mut observer = Observer::new(vec![]);
        observer.observe(&make_modbus_packet("10.0.0.1", "10.0.0.2", 0xFF));

        let obs = observer.observations();
        let summary = obs
            .modbus_flow_summary
            .get(&(ip("10.0.0.1"), ip("10.0.0.2")))
            .expect("EC-002: modbus_flow_summary entry must exist for unit_id=0xFF");
        assert!(
            summary.unit_ids.contains(&255u8),
            "EC-002: unit_id=0xFF (gateway/reserved) must be present in unit_ids"
        );
    }
}
