//! Composed Kani proofs (cross-module).
//!
//! Wave-1 (S-4.01..03) shipped the three component proofs inline in
//! `src/scrub.rs` and `src/ai/leak_detector.rs`. This module hosts
//! proofs that compose those components — currently:
//! - `composed_privacy_invariant` (BC-5.02.003) — scrub then leak-check
//!   either removes every real value OR returns Err.

#![allow(dead_code)]  // Kani-only module

use crate::scrub::ScrubMap;
use crate::ai::leak_detector;

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(SOME_BOUND)]  // TODO(S-4.04 step 4): set the actual unwind bound
    fn composed_privacy_invariant() {
        // TODO(S-4.04 step 4): implement the composed harness
        //   1. Symbolic input bytes (bounded length)
        //   2. Build a ScrubMap that maps a known real value -> a pseudonym
        //   3. Run scrub on the symbolic input
        //   4. Run leak_detector::ensure_clean on the scrub output
        //   5. Assert: either the real value is absent from the bytes, OR ensure_clean returned Err
        todo!("composed_privacy_invariant — implement in step 4")
    }
}
