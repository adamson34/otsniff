//! PCAP/PCAPNG iteration with L2/L3/L4 decoding.
//!
//! Yields owned `Packet` records so the rest of the pipeline doesn't have to
//! reason about the underlying reader's lifetimes. For v0.1 sizes (a few GB
//! at the very most) the per-packet allocation cost is fine; if it ever
//! becomes a hotspot we can switch to a callback-based API.

use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{create_reader, Linktype, PcapBlockOwned, PcapError};

use crate::error::{OtError, Result};
// progress::ProgressReporter is imported here so that cli.rs can pass one
// into the parse path (Step 4 wiring).  The type is not yet consumed by
// iter_packets; the implementer will thread it through in Step 4.
#[allow(unused_imports)]
use crate::progress::ProgressReporter;

#[derive(Debug, Clone)]
pub struct Packet {
    pub ts: DateTime<Utc>,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub transport: Transport,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Other(u8),
}

pub fn iter_packets(path: &Path) -> Result<PacketIter> {
    let file = File::open(path).map_err(|source| OtError::InputOpen {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = create_reader(1 << 20, file).map_err(|e| OtError::BadInput {
        path: path.to_path_buf(),
        reason: format!("{e:?}"),
    })?;
    Ok(PacketIter {
        reader,
        link_type: None,
    })
}

pub struct PacketIter {
    reader: Box<dyn PcapReaderIterator>,
    link_type: Option<Linktype>,
}

/// Peek a capture's declared link-layer type without decoding its packets
/// (S-9.01 / BC-1.01.004).
///
/// Returns `Ok(Some(lt))` when the type is determinate — a legacy pcap's
/// 24-byte global header `network` field, or a pcapng's first Interface
/// Description Block. Returns `Ok(None)` when the type is *indeterminate*
/// (a pcapng whose first packet block precedes any IDB, or a header we
/// couldn't read far enough to classify). Callers treat indeterminate
/// captures as Ethernet downstream (matching `decode_block`'s default) and
/// the homogeneity guard simply skips them — it only compares determinate
/// types, so an indeterminate file is never the cause of a rejection.
//
// STUB (Red Gate): real header read lands in the green step.
pub fn peek_link_type(_path: &Path) -> Result<Option<Linktype>> {
    Ok(None)
}

/// Iterator that concatenates the packet streams of several captures in
/// command-line order (S-9.01 / BC-1.01.003): every packet of `paths[0]`,
/// then every packet of `paths[1]`, and so on. No timestamp re-sort — this
/// is append (`mergecap -a`) semantics; the operator controls order.
pub struct MultiPacketIter {
    paths: std::vec::IntoIter<PathBuf>,
    current: Option<PacketIter>,
}

impl Iterator for MultiPacketIter {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Drain the current file first.
            if let Some(iter) = self.current.as_mut() {
                match iter.next() {
                    Some(item) => return Some(item),
                    None => self.current = None,
                }
            }
            // Advance to the next file. A per-file open/parse failure is
            // surfaced as an `Err` item (fail-fast) — earlier files' packets
            // have already been yielded by this point.
            match self.paths.next() {
                Some(path) => match iter_packets(&path) {
                    Ok(iter) => self.current = Some(iter),
                    Err(e) => return Some(Err(e)),
                },
                None => return None,
            }
        }
    }
}

/// Build a [`MultiPacketIter`] over `paths` after a link-layer homogeneity
/// pre-flight (S-9.01 / BC-1.01.003, BC-1.01.004).
//
// STUB (Red Gate): yields nothing and performs no guard until the green step.
pub fn iter_packets_multi(_paths: &[PathBuf]) -> Result<MultiPacketIter> {
    Ok(MultiPacketIter {
        paths: Vec::new().into_iter(),
        current: None,
    })
}

impl Iterator for PacketIter {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    let result = decode_block(&block, &mut self.link_type);
                    self.reader.consume(offset);
                    match result {
                        Ok(Some(pkt)) => return Some(Ok(pkt)),
                        Ok(None) => continue,
                        Err(e) => return Some(Err(e)),
                    }
                }
                Err(PcapError::Eof) => return None,
                Err(PcapError::Incomplete(_)) => {
                    if self.reader.refill().is_err() {
                        return Some(Err(OtError::Parse(
                            "refill failed (truncated file?)".to_string(),
                        )));
                    }
                }
                Err(e) => return Some(Err(OtError::Parse(format!("{e:?}")))),
            }
        }
    }
}

fn decode_block(
    block: &PcapBlockOwned<'_>,
    link_type: &mut Option<Linktype>,
) -> Result<Option<Packet>> {
    use pcap_parser::pcapng::Block;

    let (ts_sec, ts_nsec, data, lt) = match block {
        PcapBlockOwned::LegacyHeader(hdr) => {
            *link_type = Some(hdr.network);
            return Ok(None);
        }
        PcapBlockOwned::Legacy(rec) => {
            let lt = link_type.ok_or_else(|| OtError::Parse("missing pcap header".to_string()))?;
            // Legacy ts_usec is microseconds; convert to nanoseconds.
            (
                rec.ts_sec as i64,
                rec.ts_usec.saturating_mul(1000),
                rec.data,
                lt,
            )
        }
        PcapBlockOwned::NG(ng) => match ng {
            Block::EnhancedPacket(epb) => {
                // Proper link-type tracking via InterfaceDescription blocks
                // is a v0.2 problem. Most plant captures are Ethernet; if a
                // pcapng arrives with a different LINKTYPE we'll fail in
                // decode_ethernet rather than misparse silently.
                let lt = link_type.unwrap_or(Linktype::ETHERNET);
                let (s, n) = combine_ng_ts(epb.ts_high, epb.ts_low);
                (s, n, epb.data, lt)
            }
            Block::SimplePacket(spb) => {
                let lt = link_type.unwrap_or(Linktype::ETHERNET);
                (0, 0, spb.data, lt)
            }
            Block::SectionHeader(_) | Block::InterfaceDescription(_) => {
                // We could read the link type out of IDB here. v0.1: skip.
                return Ok(None);
            }
            _ => return Ok(None),
        },
    };

    if lt != Linktype::ETHERNET {
        return Err(OtError::UnsupportedLinkType(format!("{lt:?}")));
    }

    let ts = Utc
        .timestamp_opt(ts_sec, ts_nsec)
        .single()
        .unwrap_or_else(Utc::now);

    Ok(decode_ethernet(ts, data))
}

fn combine_ng_ts(high: u32, low: u32) -> (i64, u32) {
    // PCAPNG timestamps default to microseconds since epoch in a 64-bit
    // field (split high/low). Different units are possible via the
    // InterfaceDescription if_tsresol option — v0.1 assumes the default.
    let combined: u64 = ((high as u64) << 32) | (low as u64);
    let secs = (combined / 1_000_000) as i64;
    let nsecs = ((combined % 1_000_000) as u32).saturating_mul(1000);
    (secs, nsecs)
}

fn decode_ethernet(ts: DateTime<Utc>, frame: &[u8]) -> Option<Packet> {
    let sliced = SlicedPacket::from_ethernet(frame).ok()?;
    let link = sliced.link.as_ref()?;
    let (src_mac, dst_mac) = match link {
        etherparse::LinkSlice::Ethernet2(eth) => (eth.source(), eth.destination()),
        _ => return None,
    };

    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => {
            let h = ipv4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
            )
        }
        NetSlice::Ipv6(ipv6) => {
            let h = ipv6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
            )
        }
        // etherparse 0.20 added an ARP variant to NetSlice. ARP frames carry
        // no IP layer, so there's nothing to build a Packet from — skip them,
        // consistent with how non-Ethernet2 links and non-TCP/UDP transports
        // are dropped below.
        NetSlice::Arp(_) => return None,
    };

    let (transport, src_port, dst_port, payload) = match sliced.transport.as_ref() {
        Some(TransportSlice::Tcp(tcp)) => (
            Transport::Tcp,
            tcp.source_port(),
            tcp.destination_port(),
            tcp.payload().to_vec(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            Transport::Udp,
            udp.source_port(),
            udp.destination_port(),
            udp.payload().to_vec(),
        ),
        _ => (Transport::Other(0), 0, 0, Vec::new()),
    };

    Some(Packet {
        ts,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        transport,
        src_port,
        dst_port,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn epoch() -> DateTime<Utc> {
        Utc.timestamp_opt(0, 0).single().unwrap()
    }

    /// Build a minimal Ethernet/IPv4/TCP frame for the synthetic fixtures.
    fn eth_frame() -> Vec<u8> {
        let payload = [0xde, 0xad];
        let builder = PacketBuilder::ethernet2(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        )
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64)
        .tcp(40000, 502, 0, 1024);
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut frame, &payload).unwrap();
        frame
    }

    /// Synthesize a single-packet little-endian legacy pcap file (24-byte
    /// global header + 16-byte record header + frame), with an explicit
    /// `network` link type and packet timestamp.
    fn legacy_pcap_bytes(network: u32, ts_sec: u32, frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // Global header (little-endian, microsecond-precision magic).
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // magic
        out.extend_from_slice(&2u16.to_le_bytes()); // version major
        out.extend_from_slice(&4u16.to_le_bytes()); // version minor
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&network.to_le_bytes()); // network (link type)
        // Record header.
        out.extend_from_slice(&ts_sec.to_le_bytes()); // ts_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
        out.extend_from_slice(frame);
        out
    }

    /// AC-002: two single-packet legacy fixtures chained yield exactly two
    /// packets, in file (CLI) order, preserving per-packet timestamps.
    #[test]
    fn multi_iter_yields_packets_in_file_order() {
        let frame = eth_frame();
        let a = legacy_pcap_bytes(1, 100, &frame); // ts_sec = 100
        let b = legacy_pcap_bytes(1, 200, &frame); // ts_sec = 200
        let dir = tempfile::tempdir().unwrap();
        let pa = dir.path().join("a.pcap");
        let pb = dir.path().join("b.pcap");
        std::fs::write(&pa, &a).unwrap();
        std::fs::write(&pb, &b).unwrap();

        let pkts: Vec<Packet> = iter_packets_multi(&[pa, pb])
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(pkts.len(), 2, "expected 2 packets across the two files");
        // File order honored (no timestamp re-sort): a's packet (ts 100)
        // precedes b's (ts 200).
        assert!(
            pkts[0].ts < pkts[1].ts,
            "concatenation must preserve per-file timestamps in CLI order"
        );
    }

    /// AC-003: peek_link_type reads the legacy global header's network field.
    #[test]
    fn peek_link_type_reads_legacy_network_field() {
        let frame = eth_frame();
        let bytes = legacy_pcap_bytes(1, 100, &frame);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("eth.pcap");
        std::fs::write(&p, &bytes).unwrap();
        assert_eq!(peek_link_type(&p).unwrap(), Some(Linktype::ETHERNET));
    }

    /// AC-003: two ETHERNET fixtures pass the homogeneity guard.
    #[test]
    fn multi_iter_same_link_type_is_allowed() {
        let frame = eth_frame();
        let dir = tempfile::tempdir().unwrap();
        let pa = dir.path().join("a.pcap");
        let pb = dir.path().join("b.pcap");
        std::fs::write(&pa, legacy_pcap_bytes(1, 100, &frame)).unwrap();
        std::fs::write(&pb, legacy_pcap_bytes(1, 200, &frame)).unwrap();
        assert!(iter_packets_multi(&[pa, pb]).is_ok());
    }

    /// AC-003: an ETHERNET fixture + a LINUX_SLL (113) header → MixedLinkTypes
    /// naming both files and both type names.
    #[test]
    fn multi_iter_mixed_link_types_are_rejected() {
        let frame = eth_frame();
        let dir = tempfile::tempdir().unwrap();
        let pe = dir.path().join("eth.pcap");
        let ps = dir.path().join("sll.pcap");
        std::fs::write(&pe, legacy_pcap_bytes(1, 100, &frame)).unwrap();
        std::fs::write(&ps, legacy_pcap_bytes(113, 100, &frame)).unwrap();

        let err = match iter_packets_multi(&[pe, ps]) {
            Ok(_) => panic!("expected MixedLinkTypes, got Ok"),
            Err(e) => e,
        };
        match err {
            OtError::MixedLinkTypes {
                first_file,
                first_type,
                second_file,
                second_type,
            } => {
                let files = format!("{first_file} {second_file}");
                assert!(files.contains("eth.pcap"), "files were: {files}");
                assert!(files.contains("sll.pcap"), "files were: {files}");
                let types = format!("{first_type} {second_type}");
                assert!(types.contains("ETHERNET"), "types were: {types}");
                assert!(types.contains("LINUX_SLL"), "types were: {types}");
            }
            other => panic!("expected MixedLinkTypes, got {other:?}"),
        }
    }

    /// AC-003: a single-file list never triggers the guard.
    #[test]
    fn single_file_never_triggers_guard() {
        let frame = eth_frame();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("only.pcap");
        std::fs::write(&p, legacy_pcap_bytes(113, 100, &frame)).unwrap();
        // Even a lone non-ETHERNET file passes the guard (nothing to compare);
        // it would only fail later in decode, not here.
        assert!(iter_packets_multi(&[p]).is_ok());
    }

    /// AC-002: a path list whose second entry is missing → the iterator
    /// surfaces an Err naming the missing file, after the first file's
    /// packets have been yielded (no panic, fail-fast).
    #[test]
    fn missing_second_file_surfaces_error_after_first() {
        let frame = eth_frame();
        let dir = tempfile::tempdir().unwrap();
        let pa = dir.path().join("a.pcap");
        std::fs::write(&pa, legacy_pcap_bytes(1, 100, &frame)).unwrap();
        let missing = dir.path().join("missing.pcap");

        let mut iter = iter_packets_multi(&[pa, missing.clone()]).unwrap();
        // First file's packet is yielded.
        let first = iter.next().expect("expected first file's packet");
        assert!(first.is_ok(), "first file's packet should decode cleanly");
        // Advancing into the missing file surfaces a path-naming error.
        match iter.next() {
            Some(Err(OtError::InputOpen { path, .. })) => {
                assert!(
                    path.ends_with("missing.pcap"),
                    "error must name the missing file, got {}",
                    path.display()
                );
            }
            other => panic!("expected InputOpen err for missing file, got {other:?}"),
        }
    }

    #[test]
    fn arp_frame_is_skipped() {
        // Ethernet II frame carrying an ARP request (the classic 42-byte
        // layout). etherparse 0.20 surfaces this as NetSlice::Arp; otsniff has
        // no IP layer to build a Packet from, so decode_ethernet must drop it.
        let frame: [u8; 42] = [
            // dst MAC (broadcast) / src MAC
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            // ethertype = ARP (0x0806)
            0x08, 0x06, // htype=1, ptype=0x0800, hlen=6, plen=4, oper=1 (request)
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // sender MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender IP 192.168.1.1
            0xc0, 0xa8, 0x01, 0x01, // target MAC (unknown)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target IP 192.168.1.2
            0xc0, 0xa8, 0x01, 0x02,
        ];
        assert!(decode_ethernet(epoch(), &frame).is_none());
    }

    #[test]
    fn ipv4_tcp_frame_decodes() {
        // Guards the IP/TCP happy path across the etherparse 0.15 -> 0.20 bump.
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let builder = PacketBuilder::ethernet2(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        )
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 64)
        .tcp(40000, 502, 0, 1024);
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut frame, &payload).unwrap();

        let pkt = decode_ethernet(epoch(), &frame).expect("ipv4/tcp frame should decode");
        assert_eq!(pkt.transport, Transport::Tcp);
        assert_eq!(pkt.src_port, 40000);
        assert_eq!(pkt.dst_port, 502);
        assert_eq!(pkt.src_ip, IpAddr::V4([192, 168, 1, 10].into()));
        assert_eq!(pkt.dst_ip, IpAddr::V4([192, 168, 1, 20].into()));
        assert_eq!(pkt.payload, payload);
    }
}
