//! `otsniff slice` — extract a small, targeted PCAP from a large one (P1-7).
//!
//! Investigating a flagged Modbus write today means opening the original
//! (potentially gigabyte-sized) capture in Wireshark and hand-filtering it.
//! `slice` produces a much smaller PCAP containing only the packets that
//! match a host or flow filter, loads instantly, and is small enough to
//! attach to a ticket or hand to a vendor.
//!
//! v1 ships `--host` and `--flow` filtering. `--finding <ID>` (slice by
//! which packets contributed to a specific finding) is deliberately
//! deferred: it needs per-event packet provenance threaded through every
//! protocol parser and detector, a materially larger change than this
//! self-contained filter-and-copy path. See `docs/ROADMAP.md` P1-7.
//!
//! **Fidelity:** output packets are the *exact, verbatim* bytes captured
//! from the source file — not a reconstruction from decoded fields — so
//! checksums, options, and any unusual framing survive the trip unchanged.
//! The output is always written as a classic (legacy) pcap file regardless
//! of whether the input was legacy pcap or pcapng; that keeps the writer
//! trivial (no new dependency — ADR-0001) and the result is exactly as
//! Wireshark/tshark-readable either way.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};

use crate::error::{OtError, Result};
use crate::pcap::{iter_packets_raw, Packet};

/// One `--flow SRC=DST:PORT` selector: an exact, directional match on
/// source IP, destination IP, and destination port. Proto-agnostic (matches
/// both TCP and UDP on that port) — the common case is "show me everything
/// on this port between these two hosts," and splitting by transport adds
/// a flag most callers won't use.
#[derive(Debug, Clone, Copy)]
pub struct FlowFilter {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
}

impl FlowFilter {
    fn matches(&self, pkt: &Packet) -> bool {
        pkt.src_ip == self.src && pkt.dst_ip == self.dst && pkt.dst_port == self.dst_port
    }
}

impl FromStr for FlowFilter {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (lhs, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("'{s}' is missing ':PORT' (expected SRC=DST:PORT)"))?;
        let (src_str, dst_str) = lhs
            .split_once('=')
            .ok_or_else(|| format!("'{s}' is missing '=' (expected SRC=DST:PORT)"))?;
        let src = src_str
            .parse::<IpAddr>()
            .map_err(|e| format!("'{s}': invalid SRC — {e}"))?;
        let dst = dst_str
            .parse::<IpAddr>()
            .map_err(|e| format!("'{s}': invalid DST — {e}"))?;
        let dst_port = port_str
            .parse::<u16>()
            .map_err(|e| format!("'{s}': invalid PORT — {e}"))?;
        Ok(FlowFilter { src, dst, dst_port })
    }
}

/// True if `pkt` matches any declared host (as source or destination) or
/// any declared flow. Callers with both empty should not call this — clap's
/// `ArgGroup` on `SliceArgs` requires at least one.
fn matches(pkt: &Packet, hosts: &[IpAddr], flows: &[FlowFilter]) -> bool {
    hosts.iter().any(|h| pkt.src_ip == *h || pkt.dst_ip == *h)
        || flows.iter().any(|f| f.matches(pkt))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SliceSummary {
    pub scanned: u64,
    pub matched: u64,
}

/// Reads `input`, keeps every packet matching `hosts` or `flows`, and
/// writes them — verbatim, in original order — to a new legacy-pcap file
/// at `output`. Always writes a valid pcap, even with zero matches (an
/// empty capture is a legitimate, openable result, not an error).
pub fn run(
    input: &Path,
    output: &Path,
    hosts: &[IpAddr],
    flows: &[FlowFilter],
) -> Result<SliceSummary> {
    let mut summary = SliceSummary::default();
    let mut writer = PcapWriter::create(output)?;

    for item in iter_packets_raw(input)? {
        let (pkt, frame) = item?;
        summary.scanned += 1;
        if matches(&pkt, hosts, flows) {
            summary.matched += 1;
            writer.write_packet(pkt.ts, &frame)?;
        }
    }

    writer.finish()?;
    Ok(summary)
}

/// Minimal classic-pcap (libpcap) writer: 24-byte global header, then one
/// 16-byte record header + raw frame per packet. Microsecond timestamp
/// resolution (magic `0xa1b2c3d4`), snaplen 262144 (matches modern
/// `tcpdump`/Wireshark defaults — big enough that we never actually
/// truncate a captured frame), linktype 1 (Ethernet). See
/// <https://wiki.wireshark.org/Development/LibpcapFileFormat>.
struct PcapWriter {
    out: BufWriter<File>,
    path: PathBuf,
}

const SNAPLEN: u32 = 262_144;
const LINKTYPE_ETHERNET: u32 = 1;

impl PcapWriter {
    fn create(path: &Path) -> Result<Self> {
        let file = File::create(path).map_err(|source| OtError::WriteOutput {
            path: path.to_path_buf(),
            source,
        })?;
        let mut writer = PcapWriter {
            out: BufWriter::new(file),
            path: path.to_path_buf(),
        };
        writer.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        writer.write_all(&2u16.to_le_bytes())?; // version_major
        writer.write_all(&4u16.to_le_bytes())?; // version_minor
        writer.write_all(&0i32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&SNAPLEN.to_le_bytes())?;
        writer.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        Ok(writer)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.out
            .write_all(bytes)
            .map_err(|source| OtError::WriteOutput {
                path: self.path.clone(),
                source,
            })
    }

    fn write_packet(&mut self, ts: DateTime<Utc>, frame: &[u8]) -> Result<()> {
        let ts_sec = ts.timestamp().max(0) as u32;
        let ts_usec = ts.timestamp_subsec_micros();
        // Captured length is never truncated to SNAPLEN — we always keep
        // the exact original frame; SNAPLEN is a declared ceiling only.
        let incl_len = frame.len() as u32;
        self.write_all(&ts_sec.to_le_bytes())?;
        self.write_all(&ts_usec.to_le_bytes())?;
        self.write_all(&incl_len.to_le_bytes())?;
        self.write_all(&incl_len.to_le_bytes())?; // orig_len == incl_len (no truncation)
        self.write_all(frame)?;
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.out.flush().map_err(|source| OtError::WriteOutput {
            path: self.path.clone(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::iter_packets;
    use etherparse::PacketBuilder;
    use tempfile::TempDir;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn eth_frame(src_ip: [u8; 4], dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0x00; 6], [0x11; 6])
            .ipv4(src_ip, dst_ip, 64)
            .tcp(4000, dst_port, 1, 4096);
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    fn write_source_pcap(path: &Path, frames: &[Vec<u8>]) {
        let mut w = PcapWriter::create(path).unwrap();
        for f in frames {
            w.write_packet(Utc::now(), f).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn flow_filter_parses_and_matches() {
        let f: FlowFilter = "10.0.0.1=10.0.0.2:502".parse().unwrap();
        assert_eq!(f.src, ip("10.0.0.1"));
        assert_eq!(f.dst, ip("10.0.0.2"));
        assert_eq!(f.dst_port, 502);
    }

    #[test]
    fn flow_filter_rejects_malformed_input() {
        assert!("10.0.0.1-10.0.0.2:502".parse::<FlowFilter>().is_err());
        assert!("10.0.0.1=10.0.0.2".parse::<FlowFilter>().is_err());
        assert!("10.0.0.1=10.0.0.2:not-a-port"
            .parse::<FlowFilter>()
            .is_err());
    }

    #[test]
    fn slice_by_host_keeps_only_matching_packets_verbatim() {
        let tmp = TempDir::new().unwrap();
        let src_path = tmp.path().join("src.pcap");
        let out_path = tmp.path().join("out.pcap");

        let keep = eth_frame([10, 0, 0, 1], [10, 0, 0, 9], 502, b"keep-me");
        let drop = eth_frame([10, 0, 0, 2], [10, 0, 0, 9], 502, b"drop-me");
        write_source_pcap(&src_path, &[keep.clone(), drop]);

        let summary = run(&src_path, &out_path, &[ip("10.0.0.1")], &[]).unwrap();
        assert_eq!(summary.scanned, 2);
        assert_eq!(summary.matched, 1);

        // Re-read the sliced output through the normal decode path: exactly
        // one packet, and its payload is byte-identical to the source frame
        // (proves we copied the verbatim frame, not a reconstruction).
        let out_packets: Vec<_> = iter_packets(&out_path)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(out_packets.len(), 1);
        assert_eq!(out_packets[0].src_ip, ip("10.0.0.1"));
        assert_eq!(out_packets[0].payload, b"keep-me");
    }

    #[test]
    fn slice_by_flow_is_directional() {
        let tmp = TempDir::new().unwrap();
        let src_path = tmp.path().join("src.pcap");
        let out_path = tmp.path().join("out.pcap");

        let forward = eth_frame([10, 0, 0, 1], [10, 0, 0, 2], 502, b"a-to-b");
        let reverse = eth_frame([10, 0, 0, 2], [10, 0, 0, 1], 502, b"b-to-a");
        write_source_pcap(&src_path, &[forward, reverse]);

        let flow: FlowFilter = "10.0.0.1=10.0.0.2:502".parse().unwrap();
        let summary = run(&src_path, &out_path, &[], &[flow]).unwrap();
        assert_eq!(summary.matched, 1);

        let out_packets: Vec<_> = iter_packets(&out_path)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(out_packets.len(), 1);
        assert_eq!(out_packets[0].payload, b"a-to-b");
    }

    #[test]
    fn zero_matches_still_writes_a_valid_empty_pcap() {
        let tmp = TempDir::new().unwrap();
        let src_path = tmp.path().join("src.pcap");
        let out_path = tmp.path().join("out.pcap");
        write_source_pcap(
            &src_path,
            &[eth_frame([10, 0, 0, 1], [10, 0, 0, 9], 502, b"x")],
        );

        let summary = run(&src_path, &out_path, &[ip("9.9.9.9")], &[]).unwrap();
        assert_eq!(summary.matched, 0);

        let out_packets: Vec<_> = iter_packets(&out_path)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert!(out_packets.is_empty());
    }
}
