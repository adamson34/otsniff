use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use otsniff::parse::enip;

fn bench_parse_enip(c: &mut Criterion) {
    // Minimal EtherNet/IP encapsulation header: RegisterSession (0x0065),
    // length=4, session=0, followed by 4 bytes of payload data (28 bytes total).
    let mut frame = vec![0u8; 28];
    // command = 0x0065 LE
    frame[0] = 0x65;
    frame[1] = 0x00;
    // length = 0x0004 LE
    frame[2] = 0x04;
    frame[3] = 0x00;

    c.bench_function("parse_enip_header", |b| {
        b.iter(|| enip::parse_header(black_box(&frame)))
    });

    // SendRRData frame for engineering_class_cip bench.
    // command=0x006F, length=0x0010, session=0x00000001.
    // CPF: 6 bytes interface+timeout, then CIP Stop service (0x07).
    let mut rr_frame = vec![0u8; 38];
    rr_frame[0] = 0x6F;
    rr_frame[1] = 0x00;
    rr_frame[2] = 0x0E;
    rr_frame[3] = 0x00;
    rr_frame[4] = 0x01; // session lo
                        // offset 30 = HEADER_LEN(24) + 6 (interface+timeout) = Stop service code
    rr_frame[30] = 0x07; // CipService::Stop

    let rr_frame_static = rr_frame.clone();
    c.bench_function("parse_enip_cip", |b| {
        b.iter(|| enip::engineering_class_cip(black_box(&rr_frame_static)))
    });
}

criterion_group!(benches, bench_parse_enip);
criterion_main!(benches);
