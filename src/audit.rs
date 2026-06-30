//! Privacy-ledger audit log for the `analyze` flow.
//!
//! Produces a chain-of-custody artifact that demonstrates the scrub +
//! leak-detector invariant held for a given AI invocation:
//!
//! - what was extracted from the PCAP (counts only, no identifiers)
//! - the size of the scrub map by class
//! - the leak-detector verdict (regex + map-value, both must pass)
//! - SHA-256 of the exact bytes the AI provider was given (system
//!   prompt + user message) and the bytes it returned
//! - timing + model invoked
//!
//! Critically the log carries **hashes, not bytes**. No real
//! identifiers, no plant content. A reviewer can show that on date X
//! we invoked the provider with bytes of hash Y, and the snapshot-
//! tested leak detector guarantees that any such bytes are scrub-clean.
//!
//! See `docs/audits/scrub-audit-cip011.md` for the broader privacy
//! framing. This file is the per-run artifact that complements the
//! per-feature audit.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{OtError, Result};

/// Bump when the on-disk schema changes in a way external tooling
/// would care about.
///
/// v2 (S-9.01): `input_pcap: InputDescriptor` became
/// `input_pcaps: Vec<InputDescriptor>` to attribute a multi-file
/// (rotated-capture) analyze run to each source file.
pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize)]
pub struct AuditLog {
    pub schema_version: u32,
    pub otsniff_version: String,
    pub timestamp: DateTime<Utc>,
    /// One descriptor per input PCAP, in command-line order (S-9.01).
    /// Each `path` is a basename only (F-ADV-P2-009); each `sha256` still
    /// pins the exact bytes ingested from that file (BC-7.01.002).
    pub input_pcaps: Vec<InputDescriptor>,
    pub scrub: ScrubSummary,
    pub leak_check: LeakCheckSummary,
    pub ai_provider: AiInvocationSummary,
    pub unscrub: UnscrubSummary,
    /// SHA-256 hashes and metadata for the augment pass (S-5.03 AC-006).
    /// `None` when `--ai` is not set or when the augment pass was not
    /// requested for this run.
    pub augment_pass: Option<AugmentInvocationSummary>,
}

/// SHA-256 hashes and metadata for the AI augment pass (S-5.03).
///
/// Recorded separately from `AiInvocationSummary` (the analyze pass) so
/// auditors can independently verify both steps. Mirrors the field layout
/// of [`AiInvocationSummary`] for consistency.
#[derive(Debug, Clone, Serialize)]
pub struct AugmentInvocationSummary {
    pub system_prompt_bytes: usize,
    pub system_prompt_sha256: String,
    pub user_message_bytes: usize,
    pub user_message_sha256: String,
    pub response_bytes: usize,
    pub response_sha256: String,
    pub elapsed_seconds: f64,
    /// Number of `AugmentedFinding`s returned by the provider before dedup.
    pub raw_finding_count: usize,
    /// Number of `AugmentedFinding`s surviving dedup against rule findings.
    pub surviving_finding_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputDescriptor {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScrubSummary {
    pub ip_pseudonyms: usize,
    pub mac_pseudonyms: usize,
    pub hostname_pseudonyms: usize,
}

impl ScrubSummary {
    pub fn total(&self) -> usize {
        self.ip_pseudonyms + self.mac_pseudonyms + self.hostname_pseudonyms
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LeakCheckSummary {
    pub regex: LeakCheckResult,
    pub map_value: LeakCheckResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct LeakCheckResult {
    pub passed: bool,
    /// For regex: count of patterns the scanner looked for. For map-
    /// value: count of real values verified absent in the payload.
    pub items_checked: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiInvocationSummary {
    pub command: String,
    pub model: String,
    pub system_prompt_bytes: usize,
    pub system_prompt_sha256: String,
    pub user_message_bytes: usize,
    pub user_message_sha256: String,
    pub response_bytes: usize,
    pub response_sha256: String,
    pub elapsed_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UnscrubSummary {
    pub pseudonyms_replaced: usize,
    pub pseudonyms_unmapped: usize,
}

/// Hash a string with SHA-256, hex-encoded.
pub fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex_lower(&hasher.finalize())
}

/// Hash a file's contents with SHA-256. Streams the read so a 200 MB
/// PCAP doesn't load entirely into memory.
pub fn sha256_file_hex(path: &Path) -> Result<(u64, String)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|source| OtError::InputOpen {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).map_err(|source| OtError::InputOpen {
            path: path.to_path_buf(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex_lower(&hasher.finalize())))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_stable() {
        // Known SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn audit_log_serializes_with_no_real_identifiers() {
        // Build a log with synthetic counts only and check the JSON
        // doesn't contain anything that could pattern-match a real
        // identifier.
        let log = AuditLog {
            schema_version: SCHEMA_VERSION,
            otsniff_version: "0.3.0-test".to_string(),
            timestamp: Utc::now(),
            input_pcaps: vec![InputDescriptor {
                path: "x.pcap".to_string(),
                size_bytes: 42,
                sha256: sha256_hex(""),
            }],
            scrub: ScrubSummary {
                ip_pseudonyms: 12,
                mac_pseudonyms: 8,
                hostname_pseudonyms: 0,
            },
            leak_check: LeakCheckSummary {
                regex: LeakCheckResult {
                    passed: true,
                    items_checked: 3,
                },
                map_value: LeakCheckResult {
                    passed: true,
                    items_checked: 20,
                },
            },
            ai_provider: AiInvocationSummary {
                command: "claude -p".to_string(),
                model: "default".to_string(),
                system_prompt_bytes: 1024,
                system_prompt_sha256: sha256_hex("sys"),
                user_message_bytes: 6420,
                user_message_sha256: sha256_hex("user"),
                response_bytes: 4127,
                response_sha256: sha256_hex("resp"),
                elapsed_seconds: 8.4,
            },
            unscrub: UnscrubSummary {
                pseudonyms_replaced: 14,
                pseudonyms_unmapped: 0,
            },
            augment_pass: None,
        };
        let json = serde_json::to_string_pretty(&log).unwrap();
        // The leak detector — the same one the analyze pipeline uses —
        // is what really enforces this; here we just sanity check that
        // a plain log doesn't carry any obvious leak.
        assert!(crate::ai::leak_detector::scan(&json).is_none());
    }

    #[test]
    fn input_pcaps_serializes_as_array_with_schema_v2() {
        // S-9.01 AC-004: a two-input run serializes `input_pcaps` as a
        // 2-element array (basename + size + sha256 each), and the schema
        // bumps to 2 to signal the shape change.
        let log = AuditLog {
            schema_version: SCHEMA_VERSION,
            otsniff_version: "0.6.0-test".to_string(),
            timestamp: Utc::now(),
            input_pcaps: vec![
                InputDescriptor {
                    path: "capture-01.pcap".to_string(),
                    size_bytes: 100,
                    sha256: sha256_hex("a"),
                },
                InputDescriptor {
                    path: "capture-02.pcap".to_string(),
                    size_bytes: 200,
                    sha256: sha256_hex("b"),
                },
            ],
            scrub: ScrubSummary::default(),
            leak_check: LeakCheckSummary {
                regex: LeakCheckResult {
                    passed: true,
                    items_checked: 3,
                },
                map_value: LeakCheckResult {
                    passed: true,
                    items_checked: 0,
                },
            },
            ai_provider: AiInvocationSummary {
                command: "claude -p".to_string(),
                model: "default".to_string(),
                system_prompt_bytes: 0,
                system_prompt_sha256: sha256_hex(""),
                user_message_bytes: 0,
                user_message_sha256: sha256_hex(""),
                response_bytes: 0,
                response_sha256: sha256_hex(""),
                elapsed_seconds: 0.0,
            },
            unscrub: UnscrubSummary::default(),
            augment_pass: None,
        };

        assert_eq!(log.schema_version, 2, "schema_version must bump to 2");
        assert_eq!(log.input_pcaps.len(), 2);
        assert_eq!(log.input_pcaps[0].path, "capture-01.pcap");
        assert_eq!(log.input_pcaps[1].path, "capture-02.pcap");

        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&log).unwrap()).unwrap();
        let arr = value["input_pcaps"]
            .as_array()
            .expect("input_pcaps must serialize as a JSON array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["path"], "capture-01.pcap");
        assert_eq!(arr[1]["size_bytes"], 200);
        assert_eq!(value["schema_version"], 2);
    }

    #[test]
    fn elapsed_from_duration() {
        // Sanity: Duration → f64 seconds is straightforward; this test
        // exists so a future refactor that breaks it shows up.
        let d = std::time::Duration::from_millis(8_400);
        assert!((d.as_secs_f64() - 8.4).abs() < 1e-6);
    }
}
