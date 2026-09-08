#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

// EC-001: bound input to 64 KB per call to prevent OOM in the fuzz runner.
const MAX_INPUT: usize = 64 * 1024;

// Sentinel byte that frames every synthesized "real value". It is absent
// from the pseudonym alphabet (`host_NNN` ⊂ `[a-z0-9_]`), which makes the
// leak oracle below false-positive-free by construction — see the comment
// at the oracle.
const SENTINEL: char = '\u{1}';

// This harness exercises two things:
//   1. PANIC SAFETY (BC-0.01.002): `scrub_text` must not panic on arbitrary
//      input. The fuzzer's raw bytes flow through `text` unmodified.
//   2. LEAK ORACLE (F-ADV-P2-005): `scrub_text` must not leave any real map
//      value in its output. We exercise the substitution branch (F-ADV-P1-004)
//      by ensuring the input actually contains the map's real values.
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // Carve two fuzzer-derived fragments and frame each with the SENTINEL.
    //
    // HS-006 / wave-2: a previous version carved *raw* fragments, so a short
    // numeric value (e.g. "01") could be a substring of a pseudonym
    // (`host_001`) or form at a pseudonym boundary. `scrub_text` would
    // correctly insert `host_001`, yet `ensure_no_map_values` would see the
    // "01" *inside the inserted pseudonym* and flag a false leak. Production
    // scrub maps never collide this way (real values are IPs/MACs/hostnames).
    //
    // Framing with SENTINEL — a byte that never appears in any pseudonym —
    // eliminates that entire class: `scrub_text` only ever inserts
    // pseudonyms, so a SENTINEL-framed value can appear in the output ONLY as
    // un-scrubbed residual input, i.e. a genuine leak. No substring or
    // boundary artifact can reproduce it.
    let split = std::cmp::min(12, data.len());
    let frag_1 = String::from_utf8_lossy(&data[..split]);
    let frag_2 = String::from_utf8_lossy(&data[split..std::cmp::min(split + 12, data.len())]);
    let real_1 = format!("{SENTINEL}{frag_1}{SENTINEL}");
    let real_2 = format!("{SENTINEL}{frag_2}{SENTINEL}");

    let mut ips = BTreeMap::new();
    ips.insert("host_001".to_string(), real_1.clone());
    // ScrubMap::validate rejects duplicate real values (F-W1-003).
    if real_2 != real_1 {
        ips.insert("host_002".to_string(), real_2.clone());
    }

    let map = otsniff_privacy::ScrubMap {
        version: 1,
        created_at: chrono::Utc::now(),
        ips,
        macs: BTreeMap::new(),
        names: BTreeMap::new(),
    };

    // If the synthesized map violates an invariant, abort this iteration
    // (the bug would be in the harness, not the production path).
    if map.validate().is_err() {
        return;
    }

    // Input = arbitrary fuzzer bytes (panic coverage) + the framed real
    // values (so the substitution branch has real work to do, F-ADV-P1-004).
    let text = format!("{}{}{}", String::from_utf8_lossy(data), real_1, real_2);
    let scrubbed = otsniff_privacy::scrub_text(&text, &map);

    // F-ADV-P2-005 leak oracle. Every map real value is SENTINEL-framed, so
    // any occurrence in the output is a genuine un-scrubbed leak — never a
    // pseudonym artifact. Unconditional: no skip-guard needed.
    if let Err(e) = otsniff_privacy::leak_detector::ensure_no_map_values(&scrubbed, &map) {
        panic!("F-ADV-P2-005 oracle: scrub_text left a real value from the map in its output: {e}");
    }
});
