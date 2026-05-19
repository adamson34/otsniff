use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_findings_run(c: &mut Criterion) {
    c.bench_function("findings_run_stub", |b| {
        b.iter(|| {
            // Stub: returns immediately. Implementer runs run_all_findings
            // against a fixed Observations value here.
            black_box(0u8)
        })
    });
}

criterion_group!(benches, bench_findings_run);
criterion_main!(benches);
