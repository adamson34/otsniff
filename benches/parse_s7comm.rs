use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse_s7comm(c: &mut Criterion) {
    c.bench_function("parse_s7comm_stub", |b| {
        b.iter(|| {
            // Stub: returns immediately. Implementer adds real workload.
            black_box(0u8)
        })
    });
}

criterion_group!(benches, bench_parse_s7comm);
criterion_main!(benches);
