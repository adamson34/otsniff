#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO(S-3.04 step 4): implement corpus seeding from tests/fixtures/
    // and call otsniff::parse::enip::parse() with fuzzer-provided input.
    // Bound input to 64 KB per EC-001. Assert no panic on adversarial bytes.
});
