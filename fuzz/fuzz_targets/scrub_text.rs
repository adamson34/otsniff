#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO(S-3.04 step 4): implement corpus seeding and call
    // otsniff::scrub::scrub_text() with fuzzer-provided input.
    // Bound input to 64 KB per EC-001. Assert no panic on adversarial bytes.
});
