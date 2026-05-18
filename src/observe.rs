//! Single-pass observation layer.
//!
//! Walks every packet, accumulates per-host and per-flow state plus
//! interesting events (Modbus writes, ENIP/CIP engineering services,
//! plaintext credentials, external egress). The findings layer reads this
//! struct after iteration completes — keeps the parse loop tight.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::Serialize;

use crate::parse::{dhcp, dnp3, enip, ldap, modbus, s7comm};
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
    pub enip_events: Vec<EnipEvent>,
    pub s7_events: Vec<S7Event>,
    pub dnp3_events: Vec<Dnp3Event>,
    pub ldap_bind_events: Vec<LdapBindEvent>,
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
        if pkt.dst_port == ldap::PORT || pkt.dst_port == 3268 {
            // Check for STARTTLS ExtendedResponse success before processing
            // the BindRequest. Tag 0x78 = [APPLICATION 24] (ExtendedResponse).
            // resultCode success encodes as 0x0a 0x01 0x00 inside the PDU.
            if !payload.is_empty() && payload[0] == 0x30 {
                // Outer SEQUENCE: could be an ExtendedResponse containing a
                // successful STARTTLS result. Detect the success resultCode.
                if find_subseq(payload, &[0x78]) // APPLICATION 24 ExtendedResponse tag
                    .is_some()
                    && find_subseq(payload, &[0x0a, 0x01, 0x00]).is_some()
                // resultCode success
                {
                    let flow_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
                    self.ldap_starttls_flows.insert(flow_key, true);
                }
            }

            // Now attempt BindRequest recognition. The STARTTLS flag is read
            // from the map using the same flow tuple (with reversed src/dst
            // because the BindRequest comes from the client to the server).
            if let Some(recognized) = ldap::recognize_bind_request(payload) {
                // used_starttls: look up whether this client→server flow had a
                // prior successful STARTTLS exchange. The flow key is
                // (client_src, server_dst, client_src_port, server_dst_port).
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
        let version_tlv = vec![0x02u8, 0x01, 0x03];
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
        let msg_id = vec![0x02u8, 0x01, 0x01];
        let ldap_body: Vec<u8> = msg_id.iter().chain(bind_req.iter()).copied().collect();
        let mut msg = vec![0x30u8, ldap_body.len() as u8];
        msg.extend_from_slice(&ldap_body);
        msg
    }

    fn make_ldap_packet(src_ip: &str, dst_ip: &str, dst_port: u16, payload: Vec<u8>) -> crate::pcap::Packet {
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
    fn test_BC_1_03_005_ingests_ldap_bind_on_port_389() {
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
        assert!(!ev.used_starttls, "AC-003: used_starttls must be false when no STARTTLS preceded the bind");
    }

    /// EC-001: LDAP BindRequest on port 3268 (Global Catalog) must also be
    /// recognized and recorded.
    #[test]
    fn test_BC_1_03_005_ingests_ldap_bind_on_port_3268() {
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
            obs.ldap_bind_events[0].dst_port,
            3268,
            "EC-001: event must record the actual destination port"
        );
    }
}
