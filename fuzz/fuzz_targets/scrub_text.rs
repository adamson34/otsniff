#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

// EC-001: bound input to 64 KB per call to prevent OOM in the fuzz runner.
const MAX_INPUT: usize = 64 * 1024;

// F-ADV-P1-004: the previous harness used an empty ScrubMap, which meant
// `scrub_text` returned `text.to_string()` after the for loop iterated zero
// times — the actual substitution branch was never exercised. This version
// derives a small but non-empty map from the fuzzer's bytes so:
//   - the longest-first sort is exercised
//   - the `replace()` substitution path runs
//   - the ensure_no_map_values follow-up (which the production CLI applies
//     after `scrub_text`) has real work to do
//
// We also ALWAYS include a fixed IPv4 pseudonym in the map so even on tiny
// inputs the substitution loop has at least one entry to consider.
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // Carve a small map from the fuzzer bytes. The first up-to-12 bytes
    // become a "real value" mapped to `host_001`; the next up-to-12 bytes
    // become a second "real value" mapped to `host_002`. Both are required
    // by `ScrubMap::validate` to be non-empty; we use a fallback character
    // when the slice is empty.
    fn carve(slice: &[u8], fallback: &str) -> String {
        if slice.is_empty() {
            fallback.to_string()
        } else {
            String::from_utf8_lossy(slice).into_owned()
        }
    }

    let split = std::cmp::min(12, data.len());
    let real_1 = carve(&data[..split], "192.168.1.1");
    let real_2 = carve(
        &data[split..std::cmp::min(split + 12, data.len())],
        "10.0.0.1",
    );

    let mut ips = BTreeMap::new();
    // Fixed entry guarantees the substitution branch runs even when the
    // carved values happen to be empty or whitespace.
    ips.insert("host_000".to_string(), "192.168.255.254".to_string());
    if !real_1.is_empty() {
        ips.insert("host_001".to_string(), real_1);
    }
    // Skip the second entry only when it would collide with the first
    // (ScrubMap::validate rejects duplicate real values per F-W1-003).
    if !real_2.is_empty() && !ips.values().any(|v| v == &real_2) {
        ips.insert("host_002".to_string(), real_2);
    }

    let map = otsniff::scrub::ScrubMap {
        version: 1,
        created_at: chrono::Utc::now(),
        ips,
        macs: BTreeMap::new(),
        names: BTreeMap::new(),
    };

    // The map's invariants must hold even with fuzzer-derived content; if
    // validate() rejects, abort this iteration (the bug is in the harness,
    // not the production path being fuzzed).
    if map.validate().is_err() {
        return;
    }

    let text = String::from_utf8_lossy(data);
    let _ = otsniff::scrub::scrub_text(&text, &map);
});
