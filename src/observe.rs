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

use crate::parse::{enip, modbus};
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

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
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
pub struct CredEvent {
    pub ts: DateTime<Utc>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub kind: CredKind,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CredKind {
    FtpAuth,
    TelnetSession,
    HttpBasic,
    Snmpv1v2c,
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
    pub cred_events: Vec<CredEvent>,
    pub external_flows: HashMap<String, ExternalFlow>,
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
}

impl Observer {
    pub fn new(ot_subnets: Vec<IpNet>) -> Self {
        Self {
            ot_subnets,
            obs: Observations::default(),
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
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            proto: proto_byte,
        };
        let key_str = flow_key_str(&key);
        let label = classify_flow(pkt);
        self.obs
            .flows
            .entry(key_str)
            .and_modify(|f| {
                f.packets += 1;
                f.bytes += bytes;
                f.last_seen = pkt.ts;
                if f.label.is_none() {
                    f.label = label.clone();
                }
            })
            .or_insert_with(|| FlowObs {
                key: key.clone(),
                packets: 1,
                bytes,
                first_seen: pkt.ts,
                last_seen: pkt.ts,
                label,
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
            self.obs.cred_events.push(CredEvent {
                ts: pkt.ts,
                src: pkt.src_ip,
                dst: pkt.dst_ip,
                dst_port: 21,
                kind: CredKind::FtpAuth,
                note: first_line(payload, 80),
            });
        }

        // Telnet — any payload to/from port 23 is plaintext by definition.
        if (pkt.dst_port == 23 || pkt.src_port == 23) && !payload.is_empty() {
            self.obs.cred_events.push(CredEvent {
                ts: pkt.ts,
                src: pkt.src_ip,
                dst: pkt.dst_ip,
                dst_port: 23,
                kind: CredKind::TelnetSession,
                note: "Telnet session (cleartext)".to_string(),
            });
        }

        // HTTP basic
        if pkt.dst_port == 80 || pkt.dst_port == 8080 {
            if let Some(off) = find_subseq(payload, b"Authorization: Basic ") {
                self.obs.cred_events.push(CredEvent {
                    ts: pkt.ts,
                    src: pkt.src_ip,
                    dst: pkt.dst_ip,
                    dst_port: pkt.dst_port,
                    kind: CredKind::HttpBasic,
                    note: extract_line(payload, off, 120),
                });
            }
        }
    }

    fn observe_udp(&mut self, pkt: &Packet) {
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
                        self.obs.cred_events.push(CredEvent {
                            ts: pkt.ts,
                            src: pkt.src_ip,
                            dst: pkt.dst_ip,
                            dst_port: pkt.dst_port,
                            kind: CredKind::Snmpv1v2c,
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
    format!(
        "{}:{}->{}:{}/{}",
        k.src, k.src_port, k.dst, k.dst_port, k.proto
    )
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
            (Transport::Tcp, 443) => "https",
            (Transport::Tcp, 445) => "smb",
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
