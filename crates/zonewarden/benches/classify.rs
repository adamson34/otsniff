//! Throughput benchmark for the classify hot path (NFR-PERF).
//!
//! `classify` is the pure core's per-flow verdict engine — the inner loop run
//! once per observed flow. This bench measures single-threaded classify
//! throughput over a representative batch (mixed allowed / wrong-direction /
//! no-match / IDMZ-bypass flows) so regressions are caught against the baseline
//! recorded in `docs/performance.md`.

use std::net::IpAddr;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use zonewarden_core::classifier::{classify, ClassifyCtx};
use zonewarden_core::portset::PortSet;
use zonewarden_core::types::{
    AssetMatcher, Conduit, Direction, DstKind, Flow, MatchKind, Proto, PurdueLevel,
    ResolvedEndpoint, ResolvedPair, ServiceSource, Timestamp, ValidatedPolicy, Zone, ZoneId,
};
use zonewarden_core::validator::validate;

fn zone(id: &str, level: PurdueLevel, cidr: &str) -> Zone {
    let (addr, plen) = cidr.split_once('/').unwrap();
    Zone {
        id: ZoneId(id.to_string()),
        name: id.to_string(),
        purdue_level: level,
        sl_t: None,
        members: vec![AssetMatcher::Cidr {
            addr: addr.parse().unwrap(),
            prefix_len: plen.parse().unwrap(),
        }],
    }
}

fn policy() -> ValidatedPolicy {
    let conduits = vec![
        Conduit {
            from_zone: ZoneId("plc".into()),
            to_zone: ZoneId("hist".into()),
            direction: Direction::Forward,
            proto: Proto::Tcp,
            ports: PortSet::from_pairs(&[(502, 502)]).unwrap(),
        },
        Conduit {
            from_zone: ZoneId("hist".into()),
            to_zone: ZoneId("it".into()),
            direction: Direction::Bidirectional,
            proto: Proto::Tcp,
            ports: PortSet::from_pairs(&[(44818, 44818)]).unwrap(),
        },
    ];
    validate(zonewarden_core::types::Policy {
        zones: vec![
            zone("plc", PurdueLevel::L1, "10.0.1.0/24"),
            zone("hist", PurdueLevel::L3, "10.0.3.0/24"),
            zone("it", PurdueLevel::L4, "10.0.5.0/24"),
        ],
        conduits,
    })
    .expect("valid policy")
}

fn ep(zone_id: &str) -> ResolvedEndpoint {
    ResolvedEndpoint {
        ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
        zone_id: ZoneId(zone_id.to_string()),
        match_kind: MatchKind::Explicit { prefix_len: 24 },
    }
}

/// A representative spread of verdict outcomes, cycled to fill the batch.
fn sample(i: usize) -> (Flow, ResolvedPair, DstKind) {
    let (src, dst, port, dst_kind) = match i % 4 {
        0 => ("plc", "hist", 502, DstKind::Normal), // Allowed
        1 => ("hist", "plc", 502, DstKind::Normal), // WrongDirection
        2 => ("plc", "it", 9999, DstKind::Normal),  // NoMatchingConduit + IDMZ bypass
        _ => ("plc", "hist", 47808, DstKind::MulticastBroadcast), // MulticastExempt
    };
    let flow = Flow {
        flow_index: i as u64,
        ts: Timestamp(0),
        src_ip: "10.0.1.5".parse().unwrap(),
        src_port: Some(40000),
        dst_ip: "10.0.3.9".parse().unwrap(),
        dst_port: Some(port),
        proto: Proto::Tcp,
        service: None,
        service_source: ServiceSource::Unknown,
        conn_state: None,
    };
    let pair = ResolvedPair {
        src: ep(src),
        dst: ep(dst),
    };
    (flow, pair, dst_kind)
}

fn bench_classify(c: &mut Criterion) {
    let p = policy();
    let ctx = ClassifyCtx { policy: &p };
    let n = 10_000usize;
    let batch: Vec<(Flow, ResolvedPair, DstKind)> = (0..n).map(sample).collect();

    let mut group = c.benchmark_group("classify");
    group.throughput(Throughput::Elements(n as u64));
    group.bench_with_input(BenchmarkId::new("mixed_verdicts", n), &batch, |b, batch| {
        b.iter(|| {
            let mut acc = 0u64;
            for (flow, pair, dst_kind) in batch {
                let v = classify(&ctx, flow, pair, *dst_kind);
                acc = acc.wrapping_add(v.flow_index);
            }
            acc
        })
    });
    group.finish();
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);
