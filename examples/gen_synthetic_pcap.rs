//! Generator for `tests/fixtures/synthetic-1mb.pcap`.
//!
//! Writes a PCAP file containing synthetic Ethernet+IPv4+TCP frames with
//! Modbus/TCP payloads. Run once to regenerate the committed fixture:
//!
//!   cargo run --example gen_synthetic_pcap
//!
//! The output file is committed to the repo and used by the perf.yml CI
//! workflow for end-to-end `hyperfine` timing of `otsniff analyze`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

const TARGET_SIZE: usize = 1024 * 1024; // 1 MiB
const OUT_PATH: &str = "tests/fixtures/synthetic-1mb.pcap";

// PCAP global header (little-endian, linktype=ETHERNET=1).
fn pcap_global_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    // Standard pcap LE magic: bytes on disk = [0xd4, 0xc3, 0xb2, 0xa1].
    // A LE reader interprets this as the u32 value 0xa1b2c3d4.
    h.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
    h.extend_from_slice(&2u16.to_le_bytes()); // major version
    h.extend_from_slice(&4u16.to_le_bytes()); // minor version
    h.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    h.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    h.extend_from_slice(&1u32.to_le_bytes()); // linktype = ETHERNET
    h
}

/// Build a synthetic Ethernet+IPv4+TCP+Modbus frame.
///
/// src_ip = 10.10.0.{src_idx % 10 + 1}, dst_ip = 10.10.0.20, dst_port = 502.
fn make_frame(seq: u32) -> Vec<u8> {
    let src_octet = (seq % 10 + 1) as u8;
    let src_ip = [10, 10, 0, src_octet];
    let dst_ip = [10, 10, 0, 20u8];

    // Modbus Write Single Coil payload (12 bytes).
    let modbus: [u8; 12] = [
        0x00, 0x01, // txn id
        0x00, 0x00, // proto id
        0x00, 0x06, // length
        0x01, // unit id
        0x05, // fc: Write Single Coil
        0x00, 0x01, // output addr
        0xff, 0x00, // output value ON
    ];

    // TCP header (20 bytes, minimal, no options).
    let src_port: u16 = 50000 + (seq % 1000) as u16;
    let dst_port: u16 = 502;
    let tcp_len = 20 + modbus.len();

    // IPv4 header (20 bytes).
    let ip_total_len = (20 + tcp_len) as u16;
    let mut ip = [0u8; 20];
    ip[0] = 0x45; // version=4, ihl=5
    ip[2] = (ip_total_len >> 8) as u8;
    ip[3] = (ip_total_len & 0xff) as u8;
    ip[8] = 64; // TTL
    ip[9] = 6; // protocol TCP
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    // skip checksum (pcap-parser doesn't validate)

    let mut tcp = [0u8; 20];
    tcp[0] = (src_port >> 8) as u8;
    tcp[1] = (src_port & 0xff) as u8;
    tcp[2] = (dst_port >> 8) as u8;
    tcp[3] = (dst_port & 0xff) as u8;
    tcp[12] = 0x50; // data offset = 5 (20 bytes)
    tcp[13] = 0x18; // flags: PSH+ACK

    // Ethernet II header (14 bytes).
    let dst_mac: [u8; 6] = [0x00, 0x1b, 0x1b, 0x11, 0x22, 0x33];
    let src_mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, src_octet];
    let ethertype: [u8; 2] = [0x08, 0x00]; // IPv4

    let mut eth = Vec::with_capacity(14 + 20 + 20 + modbus.len());
    eth.extend_from_slice(&dst_mac);
    eth.extend_from_slice(&src_mac);
    eth.extend_from_slice(&ethertype);
    eth.extend_from_slice(&ip);
    eth.extend_from_slice(&tcp);
    eth.extend_from_slice(&modbus);
    eth
}

fn pcap_record_header(ts_sec: u32, ts_usec: u32, pkt_len: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.extend_from_slice(&ts_sec.to_le_bytes());
    h.extend_from_slice(&ts_usec.to_le_bytes());
    h.extend_from_slice(&(pkt_len as u32).to_le_bytes()); // incl_len
    h.extend_from_slice(&(pkt_len as u32).to_le_bytes()); // orig_len
    h
}

fn main() {
    let out_path = Path::new(OUT_PATH);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).expect("create fixtures dir");
    }
    let file = File::create(out_path).expect("create output file");
    let mut writer = BufWriter::new(file);

    writer
        .write_all(&pcap_global_header())
        .expect("write global header");

    let mut written = 24; // global header size
    let mut seq: u32 = 0;

    while written < TARGET_SIZE {
        let frame = make_frame(seq);
        let rec_hdr = pcap_record_header(
            1_700_000_000 + seq / 100,
            (seq * 10_000) % 1_000_000,
            frame.len(),
        );
        writer.write_all(&rec_hdr).expect("write record header");
        writer.write_all(&frame).expect("write frame");
        written += rec_hdr.len() + frame.len();
        seq += 1;
    }

    writer.flush().expect("flush");
    eprintln!(
        "Wrote {} packets ({} bytes) to {}",
        seq,
        written,
        out_path.display()
    );
}
