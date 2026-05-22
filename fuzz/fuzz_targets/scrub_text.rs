#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

// EC-001: bound input to 64 KB per call to prevent OOM in the fuzz runner.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let map = otsniff::scrub::ScrubMap {
        version: 1,
        created_at: chrono::Utc::now(),
        ips: BTreeMap::new(),
        macs: BTreeMap::new(),
        names: BTreeMap::new(),
    };
    let text = String::from_utf8_lossy(data);
    let _ = otsniff::scrub::scrub_text(&text, &map);
});
