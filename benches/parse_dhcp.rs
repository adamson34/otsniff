use criterion::{black_box, criterion_group, criterion_main, Criterion};
use otsniff::parse::dhcp;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const FIXED_HEADER_LEN: usize = 240;

fn bench_parse_dhcp(c: &mut Criterion) {
    // Build a minimal DHCP ACK payload:
    //   yiaddr = 10.10.10.10
    //   option 12 (hostname) = "PLC-BENCH"
    //   option 255 (end)
    let mut frame = vec![0u8; FIXED_HEADER_LEN];
    // yiaddr at offset 16
    frame[16] = 10;
    frame[17] = 10;
    frame[18] = 10;
    frame[19] = 10;
    // magic cookie at offset 236
    frame[236..240].copy_from_slice(&MAGIC_COOKIE);
    // option 12: hostname "PLC-BENCH" (9 bytes)
    let hostname = b"PLC-BENCH";
    frame.push(12); // option code
    frame.push(hostname.len() as u8);
    frame.extend_from_slice(hostname);
    frame.push(0xFF); // option end

    c.bench_function("parse_dhcp", |b| b.iter(|| dhcp::parse(black_box(&frame))));
}

criterion_group!(benches, bench_parse_dhcp);
criterion_main!(benches);
