use criterion::{black_box, criterion_group, criterion_main, Criterion};
use otsniff::parse::modbus;

fn bench_parse_modbus(c: &mut Criterion) {
    // MBAP-framed Modbus Write Single Coil request (fc=0x05).
    // txn=0x0001 proto=0x0000 len=0x0006 unit=0x01 fc=0x05 addr=0x0001 val=0xFF00
    let frame: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xff, 0x00,
    ];
    c.bench_function("parse_modbus", |b| {
        b.iter(|| modbus::parse(black_box(frame)))
    });
}

criterion_group!(benches, bench_parse_modbus);
criterion_main!(benches);
