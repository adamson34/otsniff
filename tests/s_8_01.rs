//! Integration tests for story S-8.01: mDNS / NetBIOS-NS / LLMNR hostname
//! extraction.
//!
//! These tests exercise the full pipeline from Observer → Observations → downstream
//! consumers to verify that hostnames sourced from the three new protocols are
//! correctly surfaced in the inventory (AC-005 / BC-2.01.002) and correctly
//! scrubbed (AC-006 / BC-5.02.002).

use std::net::IpAddr;

use chrono::{TimeZone, Utc};
use ipnet::IpNet;
use otsniff::inventory::build as build_inventory;
use otsniff::observe::Observer;
use otsniff::pcap::{Packet, Transport};
use otsniff::scrub::build_map_at;

fn fixed_ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Build a minimal mDNS response message (QR=1, AA=1) containing one A record
/// for `<hostname_label>.local.` → `rdata_ip`.
///
/// The packet's `src_ip` is set to the RDATA IP so the Observer also creates a
/// `HostObs` for that address (required for inventory to include the asset).
fn make_mdns_packet(hostname_label: &[u8], rdata_ip: [u8; 4]) -> Packet {
    let mut payload = vec![
        0x00, 0x00, 0x84, 0x00, // TxID, Flags (QR=1, AA=1)
        0x00, 0x00, 0x00, 0x01, // QDCOUNT=0, ANCOUNT=1
        0x00, 0x00, 0x00, 0x00, // NSCOUNT=0, ARCOUNT=0
    ];
    // Owner name: <hostname_label>.local.
    payload.push(hostname_label.len() as u8);
    payload.extend_from_slice(hostname_label);
    payload.extend_from_slice(&[0x05, b'l', b'o', b'c', b'a', b'l']); // label "local"
    payload.push(0x00); // end of name
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // RRTYPE=A, RRCLASS=IN
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x78, 0x00, 0x04]); // TTL=120, RDLEN=4
    payload.extend_from_slice(&rdata_ip); // RDATA

    Packet {
        ts: fixed_ts(),
        src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        // Use the asset's IP as src_ip so the Observer registers a HostObs for
        // it (needed for the inventory to include the asset row).
        src_ip: IpAddr::V4(rdata_ip.into()),
        dst_ip: "224.0.0.251".parse().unwrap(),
        transport: Transport::Udp,
        src_port: 5353,
        dst_port: 5353,
        payload,
    }
}

// ── AC-005 / BC-2.01.002 ──────────────────────────────────────────────────────

/// BC-2.01.002 / AC-005: an mDNS A-record observed by the observer must
/// surface as `Asset.hostname` in the inventory produced by `build_inventory`.
///
/// Pipeline under test:
///   Observer::observe(mDNS packet)
///     → obs.hostnames[10.0.0.5] = "HMI-LINE-3"
///     → build_inventory(&obs)
///     → Asset { ip: 10.0.0.5, hostname: Some("HMI-LINE-3"), … }
#[test]
fn test_bc_2_01_002_mdns_hostname_surfaces_in_inventory() {
    let pkt = make_mdns_packet(b"HMI-LINE-3", [10, 0, 0, 5]);
    let ot_subnet: IpNet = "10.0.0.0/24".parse().unwrap();

    let mut observer = Observer::new(vec![ot_subnet]);
    observer.observe(&pkt);
    let obs = observer.finish();

    let inventory = build_inventory(&obs);
    let asset = inventory.iter().find(|a| a.ip == ip("10.0.0.5"));
    assert!(
        asset.is_some(),
        "BC-2.01.002 / AC-005: an asset for 10.0.0.5 must appear in the inventory \
         after the mDNS packet is observed"
    );
    assert_eq!(
        asset.unwrap().hostname,
        Some("HMI-LINE-3".to_string()),
        "BC-2.01.002 / AC-005: the mDNS-derived hostname must appear as \
         Asset.hostname in the inventory"
    );
}

// ── AC-006 / BC-5.02.002 ──────────────────────────────────────────────────────

/// BC-5.02.002 / AC-006: a hostname that enters `obs.hostnames` via the mDNS
/// path must be minted as a `name_NNN` pseudonym in the scrub map — proving
/// it travels the existing scrub boundary without a new bypass.
///
/// Pipeline under test:
///   Observer::observe(mDNS packet)
///     → obs.hostnames[10.0.0.5] = "HMI-LINE-3"
///     → build_map_at(&obs, …)
///     → map.names contains some `name_NNN → "HMI-LINE-3"` entry
#[test]
fn test_bc_5_02_002_mdns_hostname_scrubbed_in_scrub_map() {
    let pkt = make_mdns_packet(b"HMI-LINE-3", [10, 0, 0, 5]);

    let mut observer = Observer::new(vec![]);
    observer.observe(&pkt);
    let obs = observer.finish();

    let map = build_map_at(&obs, fixed_ts());
    assert!(
        map.names.values().any(|v| v == "HMI-LINE-3"),
        "BC-5.02.002 / AC-006: mDNS-sourced hostname 'HMI-LINE-3' must appear \
         as a name_NNN pseudonym value in the scrub map — raw hostname must \
         not reach any AI provider"
    );
}
