pub mod ai;
pub mod audit;
pub mod bundle;
pub mod capture_sanity;
pub mod capture_source;
pub mod cli;
pub mod diff;
pub mod error;
pub mod findings;
pub mod inventory;
pub mod observe;
pub mod oui;
pub mod packs;
pub mod parse;
pub mod pcap;
pub mod progress;
pub mod report;
pub mod report_md;
pub mod rule_catalog;
pub mod scrub;
pub mod segmentation;
pub mod slice;
pub mod trusted_writer;

#[cfg(kani)]
mod kani_proofs;

pub use error::{OtError, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
