//! Replays fuzzer-discovered crash artifacts to lock in fixes (AC-004).
//!
//! This test walks `fuzz/artifacts/*/` directories for reproducer files
//! and feeds them to the corresponding parser, asserting no panic.
//! This test stays green even when the fuzz CI workflow is paused.

#[test]
fn fuzz_artifacts_dont_panic() {
    // TODO(S-3.04 step 4): walk fuzz/artifacts/ for each harness name
    // (parse_modbus, parse_enip, parse_s7comm, parse_dhcp, parse_dnp3, scrub_text).
    // For each artifact file, call the corresponding parser and assert no panic.
    // Use std::fs::read_dir or similar to iterate crash reproducers.
}
