use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_observe_pipeline(c: &mut Criterion) {
    c.bench_function("observe_pipeline_stub", |b| {
        b.iter(|| {
            // Stub: returns immediately. Implementer adds full ingest of
            // synthetic 10k-packet fixture.
            black_box(0u8)
        })
    });
}

criterion_group!(benches, bench_observe_pipeline);
criterion_main!(benches);
