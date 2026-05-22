#![no_main]

use libfuzzer_sys::fuzz_target;

// EC-001: bound input to 64 KB per call to prevent OOM in the fuzz runner.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let _ = otsniff::parse::enip::parse_header(data);
});
