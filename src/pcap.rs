//! PCAP/PCAPNG iteration with L2/L3/L4 decoding.
//!
//! Yields owned `Packet` records so the rest of the pipeline doesn't have to
//! reason about the underlying reader's lifetimes. For v0.1 sizes (a few GB
//! at the very most) the per-packet allocation cost is fine; if it ever
//! becomes a hotspot we can switch to a callback-based API.

use std::fs::File;
use std::net::IpAddr;
use std::path::Path;

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
