//! Snapshot tests for report output stability.
//!
//! Build a deterministic `Observations` fixture, run it through inventory +
//! findings + render, and snapshot both the HTML and the JSON. Any change
//! to report formatting requires explicit acceptance via
//! `cargo insta review`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};
use ipnet::IpNet;

use otsniff::findings::run_all;
use otsniff::inventory::build as build_inventory;
use otsniff::observe::{
    CredEvent, CredKind, EnipEvent, ExternalFlow, FlowKey, FlowObs, HostObs, ModbusEvent,
    Observations,
};
use otsniff::report::render_html;

fn fixed_ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
}

fn ip(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
}

fn ot_subnets() -> Vec<IpNet> {
    vec!["10.10.0.0/16".parse().unwrap()]
}

fn build_fixture() -> Observations {
    let mut hosts = HashMap::new();
    hosts.insert(
        ip("10.10.0.5"),
        HostObs {
            ip: ip("10.10.0.5"),
            macs: vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]],
            protocols: HashSet::from(["modbus".to_string(), "smb".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 250,
            bytes: 24_000,
            in_ot_zone: true,
        },
    );
    hosts.insert(
        ip("10.10.0.20"),
        HostObs {
            ip: ip("10.10.0.20"),
            macs: vec![[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]], // Siemens OUI
            protocols: HashSet::from(["modbus".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 250,
            bytes: 24_000,
            in_ot_zone: true,
        },
    );
    hosts.insert(
        ip("8.8.8.8"),
        HostObs {
            ip: ip("8.8.8.8"),
            macs: vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99]],
            protocols: HashSet::from(["http".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 5,
            bytes: 600,
            in_ot_zone: false,
        },
    );

    let mut flows = HashMap::new();
    let modbus_flow = FlowObs {
        key: FlowKey {
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            src_port: 54000,
            dst_port: 502,
            proto: 6,
        },
        packets: 500,
        bytes: 48_000,
        first_seen: fixed_ts(),
        last_seen: fixed_ts(),
        label: Some("modbus".to_string()),
    };
    flows.insert("a".to_string(), modbus_flow);

    let egress_flow = FlowObs {
        key: FlowKey {
            src: ip("10.10.0.5"),
            dst: ip("8.8.8.8"),
            src_port: 54200,
            dst_port: 80,
            proto: 6,
        },
        packets: 5,
        bytes: 600,
        first_seen: fixed_ts(),
        last_seen: fixed_ts(),
        label: Some("http".to_string()),
    };
    flows.insert("b".to_string(), egress_flow);

    let mut external_flows = HashMap::new();
    external_flows.insert(
        "ext-1".to_string(),
        ExternalFlow {
            src: ip("10.10.0.5"),
            dst: ip("8.8.8.8"),
            dst_port: 80,
            proto: 6,
            packets: 5,
            bytes: 600,
        },
    );

    Observations {
        hosts,
        flows,
        modbus_events: vec![ModbusEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            function_code: 0x05,
            label: "Write Single Coil".to_string(),
            engineering_class: true,
        }],
        enip_events: vec![EnipEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            command: 0x006F,
            command_label: "SendRRData".to_string(),
            cip_service: Some("Stop".to_string()),
            engineering_class: true,
        }],
        cred_events: vec![CredEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            dst_port: 23,
            kind: CredKind::TelnetSession,
            note: "Telnet session (cleartext)".to_string(),
        }],
        external_flows,
        first_ts: Some(fixed_ts()),
        last_ts: Some(fixed_ts()),
        total_packets: 505,
        total_bytes: 48_600,
    }
}

#[test]
fn html_report_snapshot() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
    )
    .unwrap();
    insta::assert_snapshot!("report_html", html);
}

#[test]
fn findings_json_snapshot() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let payload = serde_json::json!({
        "inventory": inventory,
        "findings": findings,
    });
    insta::assert_json_snapshot!("findings_json", payload);
}
