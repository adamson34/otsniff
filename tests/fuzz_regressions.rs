//! Replays fuzzer-discovered crash artifacts to lock in fixes (AC-004).
//! Stays green when fuzz/artifacts/ has no entries.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[test]
fn fuzz_artifacts_dont_panic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/artifacts");
    if !root.exists() {
        return; // no artifacts yet — trivially passes
    }
    for harness_dir in fs::read_dir(&root).unwrap() {
        let dir = harness_dir.unwrap();
        let name = dir.file_name();
        let name = name.to_string_lossy();
        if !dir.path().is_dir() {
            continue;
        }
        for entry in fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let data = fs::read(&path).unwrap();
            // Dispatch by harness name. Each branch calls the same entry-point
            // the corresponding harness calls. The test fails if any of these
            // panic — that's the regression signal.
            match &*name {
                "parse_modbus" => {
                    let _ = otsniff::parse::modbus::parse(&data);
                }
                "parse_enip" => {
                    let _ = otsniff::parse::enip::parse_header(&data);
                }
                "parse_s7comm" => {
                    let _ = otsniff::parse::s7comm::parse(&data);
                }
                "parse_dhcp" => {
                    let _ = otsniff::parse::dhcp::parse(&data);
                }
                "parse_dnp3" => {
                    let _ = otsniff::parse::dnp3::parse(&data);
                }
                "scrub_text" => {
                    let map = otsniff_privacy::ScrubMap {
                        version: 1,
                        created_at: chrono::Utc::now(),
                        ips: BTreeMap::new(),
                        macs: BTreeMap::new(),
                        names: BTreeMap::new(),
                    };
                    let _ = otsniff_privacy::scrub_text(&String::from_utf8_lossy(&data), &map);
                }
                _ => panic!("unknown fuzz harness directory: {name}"),
            }
        }
    }
}
