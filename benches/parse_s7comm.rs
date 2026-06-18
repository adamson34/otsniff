use criterion::{criterion_group, criterion_main, Criterion};
use otsniff::parse::s7comm;
use std::hint::black_box;

fn bench_parse_s7comm(c: &mut Criterion) {
    // Synthetic TPKT+COTP+S7 Job frame with Write Var (fc=0x05).
    // TPKT(4) + COTP(3) + S7-hdr(10) + params(2) = 19 bytes total.
    let total: u16 = 4 + 3 + 10 + 2;
    let frame: Vec<u8> = vec![
        // TPKT
        0x03,
        0x00,
        (total >> 8) as u8,
        (total & 0xff) as u8,
        // COTP DT
        0x02,
        0xF0,
        0x80,
        // S7 header: proto=0x32 rosctr=Job(0x01) res(2) ref(2) plen_be=2 dlen_be=0
        0x32,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        // params: fc=Write Var
        0x05,
        0x00,
    ];
    debug_assert_eq!(frame.len(), total as usize);

    c.bench_function("parse_s7comm", |b| {
        b.iter(|| s7comm::parse(black_box(&frame)))
    });
}

criterion_group!(benches, bench_parse_s7comm);
criterion_main!(benches);
