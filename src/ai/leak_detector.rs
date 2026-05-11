//! Fail-closed leak detection.
//!
//! Sits between the scrub layer and any AI provider call as a kill switch.
//! Even if the scrub layer has a bug — missed an observation, didn't
//! recognize a payload field, processed an unanticipated PCAP shape — this
//! verifier prevents real network identifiers from reaching the AI.
//!
//! It scans for IPv4-, IPv6-, and MAC-shaped patterns and refuses to
//! return clean if any are found. The error includes the offending
//! pattern so the user can file a precise bug report.

use regex::Regex;

use crate::error::{OtError, Result};
use crate::scrub::ScrubMap;

#[derive(Debug, Clone)]
pub struct Leak {
    pub kind: LeakKind,
    pub pattern: String,
    pub byte_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakKind {
    Ipv4,
    Ipv6,
    Mac,
}

impl LeakKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4 address",
            Self::Ipv6 => "IPv6 address",
            Self::Mac => "MAC address",
        }
    }
}

/// Scan `text` for any unscrubbed identifier-shaped pattern. Returns the
/// first leak found, or `None` if the text is clean.
///
/// We return only the first leak by design — if there's one, the calling
/// code aborts; we don't need to enumerate them all.
pub fn scan(text: &str) -> Option<Leak> {
    if let Some(m) = ipv4_regex().find(text) {
        return Some(Leak {
            kind: LeakKind::Ipv4,
            pattern: m.as_str().to_string(),
            byte_offset: m.start(),
        });
    }
    if let Some(m) = ipv6_regex().find(text) {
        return Some(Leak {
            kind: LeakKind::Ipv6,
            pattern: m.as_str().to_string(),
            byte_offset: m.start(),
        });
    }
    if let Some(m) = mac_regex().find(text) {
        return Some(Leak {
            kind: LeakKind::Mac,
            pattern: m.as_str().to_string(),
            byte_offset: m.start(),
        });
    }
    None
}

/// Convenience wrapper used at the boundary in the `analyze` pipeline.
/// Returns `Ok(())` if the text is clean, otherwise an `OtError` with
/// enough detail for the user to diagnose.
pub fn ensure_clean(text: &str) -> Result<()> {
    if let Some(leak) = scan(text) {
        return Err(OtError::Parse(format!(
            "scrub leak: refusing to send {} pattern '{}' (byte offset {}) to AI provider. \
             This is a bug — please report with the input PCAP if possible. The scrub layer \
             is supposed to remove this before the leak detector runs.",
            leak.kind.label(),
            leak.pattern,
            leak.byte_offset
        )));
    }
    Ok(())
}

/// Verify that none of the real values in the scrub map appear verbatim in
/// `text`. This is the primary defense for hostnames — they don't have a
/// clean regex shape (anything from `host42` to `LINE-3-PLC` is valid), so
/// we can't reliably regex-match them. Instead, we know exactly which real
/// hostnames the run observed and check post-scrub text against that list.
///
/// For IPs and MACs this duplicates the regex check, which is fine —
/// defense in depth, and the runtime cost is bounded by map size.
pub fn ensure_no_map_values(text: &str, map: &ScrubMap) -> Result<()> {
    for real in map.real_values() {
        if real.is_empty() {
            continue;
        }
        if text.contains(real) {
            return Err(OtError::Parse(format!(
                "scrub leak: refusing to send unscrambled identifier '{real}' to AI provider. \
                 This is a bug — the value was in the scrub map but wasn't substituted in the \
                 rendered report. Please report with the input PCAP if possible."
            )));
        }
    }
    Ok(())
}

fn ipv4_regex() -> Regex {
    // Conservative: dotted-quad with each octet 0-255 isn't strictly
    // necessary; we want to catch anything dotted-quad-shaped. The only
    // false-positive risk is a string like "1.2.3.4" appearing in
    // version numbers — acceptable; better to fail closed.
    Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid regex")
}

fn ipv6_regex() -> Regex {
    // Matches obvious IPv6 forms (full 8-group, common abbreviated forms
    // with `::`). Doesn't try to match every legal IPv6 representation.
    Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}:[0-9a-fA-F]{1,4}\b")
        .expect("valid regex")
}

fn mac_regex() -> Regex {
    // 6 colon-separated hex octets, case-insensitive.
    Regex::new(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b").expect("valid regex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_ipv4_in_otherwise_clean_text() {
        let leak = scan("the host was 192.168.1.5 doing things").unwrap();
        assert_eq!(leak.kind, LeakKind::Ipv4);
        assert_eq!(leak.pattern, "192.168.1.5");
    }

    #[test]
    fn flags_mac_in_text() {
        let leak = scan("found mac 00:1B:1B:11:22:33 on the wire").unwrap();
        assert_eq!(leak.kind, LeakKind::Mac);
    }

    #[test]
    fn flags_ipv6_in_text() {
        let leak = scan("the v6 addr 2001:db8:85a3::8a2e:370:7334 is real").unwrap();
        assert_eq!(leak.kind, LeakKind::Ipv6);
    }

    #[test]
    fn does_not_flag_pseudonyms() {
        assert!(scan("host_001 talked to mac_005 on host_007").is_none());
    }

    #[test]
    fn does_not_flag_normal_prose() {
        let prose = "## Findings\n\nThe analyst should review hosts in the OT zone. \
                     Severity: critical. Recommendation: investigate.";
        assert!(scan(prose).is_none());
    }

    #[test]
    fn ensure_clean_returns_descriptive_error() {
        let err = ensure_clean("see 10.0.0.5").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("scrub leak"));
        assert!(msg.contains("10.0.0.5"));
    }

    #[test]
    fn ensure_no_map_values_catches_hostname_leak_that_regex_misses() {
        use chrono::Utc;
        use std::collections::BTreeMap;

        // A hostname like "LINE-3-PLC" does not match the IPv4/IPv6/MAC
        // regexes — only the map-value check would catch it leaking.
        let mut names = BTreeMap::new();
        names.insert("name_001".to_string(), "LINE-3-PLC".to_string());
        let map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: BTreeMap::new(),
            macs: BTreeMap::new(),
            names,
        };

        let leaky = "Engineer connected to LINE-3-PLC and started a download.";
        assert!(scan(leaky).is_none(), "regex check should miss hostname");
        let err = ensure_no_map_values(leaky, &map).unwrap_err();
        assert!(err.to_string().contains("LINE-3-PLC"));

        let clean = "Engineer connected to name_001 and started a download.";
        assert!(ensure_no_map_values(clean, &map).is_ok());
    }
}
