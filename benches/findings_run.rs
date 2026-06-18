use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};
use criterion::{criterion_group, criterion_main, Criterion};
use ipnet::IpNet;
use std::hint::black_box;

use otsniff::findings::run_all;
use otsniff::observe::{
    CredEvent, CredKind, EnipEvent, ExternalFlow, FlowKey, FlowObs, HostObs, ModbusEvent,
    Observations, S7Event,
};

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn build_obs() -> Observations {
    let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

    let mut hosts = HashMap::new();
    hosts.insert(
        ip(10, 10, 0, 5),
        HostObs {
            ip: ip(10, 10, 0, 5),
            macs: vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]],
            protocols: HashSet::from(["modbus".to_string()]),
            first_seen: ts,
            last_seen: ts,
            packets: 250,
            bytes: 24_000,
            in_ot_zone: true,
        },
    );
    hosts.insert(
        ip(10, 10, 0, 20),
        HostObs {
            ip: ip(10, 10, 0, 20),
            macs: vec![[0x00, 0x1b, 0x1b, 0x11, 0x22, 0x33]],
            protocols: HashSet::from(["modbus".to_string()]),
            first_seen: ts,
            last_seen: ts,
            packets: 250,
            bytes: 24_000,
            in_ot_zone: true,
        },
    );
    hosts.insert(
        ip(8, 8, 8, 8),
        HostObs {
            ip: ip(8, 8, 8, 8),
            macs: vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99]],
            protocols: HashSet::from(["http".to_string()]),
            first_seen: ts,
            last_seen: ts,
            packets: 5,
            bytes: 600,
            in_ot_zone: false,
        },
    );

    let mut flows = HashMap::new();
    flows.insert(
        "a".to_string(),
        FlowObs {
            key: FlowKey {
                src: ip(10, 10, 0, 5),
                dst: ip(10, 10, 0, 20),
                dst_port: 502,
                proto: 6,
            },
            packets: 500,
            bytes: 48_000,
            first_seen: ts,
            last_seen: ts,
            label: Some("modbus".to_string()),
            unique_src_ports: HashSet::from([54000]),
        },
    );
    flows.insert(
        "b".to_string(),
        FlowObs {
            key: FlowKey {
                src: ip(10, 10, 0, 5),
                dst: ip(8, 8, 8, 8),
                dst_port: 80,
                proto: 6,
            },
            packets: 5,
            bytes: 600,
            first_seen: ts,
            last_seen: ts,
            label: Some("http".to_string()),
            unique_src_ports: HashSet::from([54200]),
        },
    );

    let mut external_flows = HashMap::new();
    external_flows.insert(
        "ext-1".to_string(),
        ExternalFlow {
            src: ip(10, 10, 0, 5),
            dst: ip(8, 8, 8, 8),
            dst_port: 80,
            proto: 6,
            packets: 5,
            bytes: 600,
        },
    );

    Observations {
        hosts,
        flows,
        modbus_flow_summary: BTreeMap::new(),
        modbus_events: vec![ModbusEvent {
            ts,
            src: ip(10, 10, 0, 5),
            dst: ip(10, 10, 0, 20),
            function_code: 0x05,
            label: "Write Single Coil".to_string(),
            engineering_class: true,
        }],
        enip_events: vec![EnipEvent {
            ts,
            src: ip(10, 10, 0, 5),
            dst: ip(10, 10, 0, 20),
            command: 0x006F,
            command_label: "SendRRData".to_string(),
            cip_service: Some("Stop".to_string()),
            engineering_class: true,
        }],
        s7_events: vec![S7Event {
            ts,
            src: ip(10, 10, 0, 5),
            dst: ip(10, 10, 0, 20),
            function_code: 0x1A,
            label: "Request download".to_string(),
            engineering_class: true,
            read_class: false,
        }],
        dnp3_events: vec![],
        ntlm_events: vec![],
        ldap_bind_events: vec![],
        rdp_events: vec![],
        cred_events: vec![CredEvent {
            ts,
            src: ip(10, 10, 0, 5),
            dst: ip(10, 10, 0, 20),
            dst_port: 23,
            kind: CredKind::TelnetSession,
            count: 1,
            note: "Telnet session (cleartext)".to_string(),
        }],
        cred_events_index: HashMap::new(),
        external_flows,
        first_ts: Some(ts),
        last_ts: Some(ts),
        total_packets: 505,
        total_bytes: 48_600,
        mac_frame_counts: BTreeMap::new(),
        broadcast_frames: 0,
        smbv1_packets: HashMap::new(),
        tls_client_hellos: HashMap::new(),
        tls_cipher_suites: HashMap::new(),
        hostnames: BTreeMap::new(),
    }
}

fn bench_findings_run(c: &mut Criterion) {
    let obs = build_obs();
    let ot_subnets: Vec<IpNet> = vec!["10.10.0.0/16".parse().unwrap()];

    c.bench_function("findings_run", |b| {
        b.iter(|| run_all(black_box(&obs), black_box(&ot_subnets)))
    });
}

criterion_group!(benches, bench_findings_run);
criterion_main!(benches);
