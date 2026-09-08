//! `otsniff-privacy` — pseudonym scrub / unscrub layer and fail-closed leak
//! detection, extracted from `otsniff` (S-13.01).
//!
//! See ADR-0006 for design rationale.

pub mod error;
pub mod leak_detector;
pub mod scrub;

pub use error::PrivacyError;
pub use scrub::ScrubMap;
