pub mod ai;
pub mod capture_source;
pub mod cli;
pub mod error;
pub mod findings;
pub mod inventory;
pub mod observe;
pub mod oui;
pub mod parse;
pub mod pcap;
pub mod report;
pub mod report_md;
pub mod rule_catalog;
pub mod scrub;

pub use error::{OtError, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
