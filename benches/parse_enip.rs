use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse_enip(c: &mut Criterion) {
    c.bench_function("parse_enip_stub", |b| {
        b.iter(|| {
            // Stub: returns immediately. Implementer adds real workload.
            black_box(0u8)
        })
    });
}

criterion_group!(benches, bench_parse_enip);
criterion_main!(benches);
