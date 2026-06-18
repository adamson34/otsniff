use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};
use ipnet::IpNet;
use otsniff::observe::Observer;
use otsniff::pcap::{Packet, Transport};

fn make_packets(n: usize) -> Vec<Packet> {
    let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    // Modbus Write Single Coil payload
    let modbus_payload: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xff, 0x00,
    ];
    (0..n)
        .map(|i| Packet {
            ts,
            src_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, (i % 256) as u8],
            dst_mac: [0x00, 0x1b, 0x1b, 0x11, 0x22, 0x33],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 0, (i % 254 + 1) as u8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 0, 20)),
            transport: Transport::Tcp,
            src_port: 50000 + (i % 1000) as u16,
            dst_port: 502,
            payload: modbus_payload.clone(),
        })
        .collect()
}

fn run_observer(packets: Vec<Packet>) -> otsniff::observe::Observations {
    let ot_subnets: Vec<IpNet> = vec!["10.10.0.0/16".parse().unwrap()];
    let mut observer = Observer::new(ot_subnets);
    for pkt in &packets {
        observer.observe(pkt);
    }
    observer.finish()
}

fn bench_observe_pipeline(c: &mut Criterion) {
    c.bench_function("observe_pipeline_100", |b| {
        b.iter_batched(
            || make_packets(100),
            |pkts| run_observer(black_box(pkts)),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_observe_pipeline);
criterion_main!(benches);
