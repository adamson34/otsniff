//! `creds.default_or_weak_credentials` finding emitter (P2-3, partial).
//!
//! Flags the subset of cleartext credential exposures (already captured as
//! `creds.ftp` / `creds.http_basic`) that are ALSO a well-known default or
//! trivially-weak value: an FTP `USER anonymous` login, or an HTTP Basic
//! password matching a small watchlist of textbook-weak values. This is a
//! stronger, more actionable signal than "cleartext exposure" alone — a
//! random cleartext password is bad; a vendor-default or top-10-weak
//! password is bad *and* guessable by anyone who's read a security
//! advisory, without ever capturing this traffic.
//!
//! **Scope note (P2-3):** the roadmap named four payload-aware findings.
//! This ships two — FTP anonymous and HTTP Basic weak/default password —
//! because both build entirely on already-captured `cred_events` data with
//! no new protocol parsing. The other two are deferred: Telnet's
//! byte-by-byte character-echo protocol means the current parser never
//! captures a clean USER/PASS pair to check (`CredEvent.note` for
//! `TelnetSession` is a constant "session observed" string, not login
//! content — session reassembly to extract it is out of scope here);
//! Siemens S7 default-password checking and "known Stuxnet-style"
//! Modbus/S7 sequences both need new protocol-specific parsing this story
//! doesn't add. See `docs/ROADMAP.md` P2-3.
//!
//! **Privacy:** `CredEvent.note` (the raw captured line — may contain a
//! real username, or a real password even when it doesn't match the
//! watchlist) is read here only to compute a match/no-match verdict. It is
//! NEVER copied into evidence — see `docs/audits/scrub-audit-cip011.md`
//! Finding #1 and the `cred_event_note_must_not_reach_any_rendered_output`
//! regression test in `tests/snapshot.rs`. Evidence states only which
//! category matched ("FTP anonymous login", "HTTP Basic — known
//! weak/default password", "HTTP Basic — empty password"), never the
//! actual captured value.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::{CredEvent, CredKind, Observations};

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

/// Small, deliberately minimal watchlist of textbook weak/default
/// passwords — not a breach-corpus wordlist (no licensing/provenance
/// question here; every one of these appears in general
/// security-awareness material). Matched case-insensitively.
const WEAK_PASSWORDS: &[&str] = &[
    "admin", "password", "123456", "12345678", "letmein", "changeme", "default", "root", "pass",
    "guest", "0000", "1234", "111111",
];

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "creds.default_or_weak_credentials",
    title: "Default or trivially-weak credentials observed in cleartext",
    severity: Severity::Critical,
    trigger: "Fires on the subset of creds.ftp / creds.http_basic events \
              that are ALSO a well-known default or weak value: an FTP \
              `USER anonymous` login, or an HTTP Basic password that is \
              empty or matches a small watchlist of textbook-weak values \
              (admin, password, 123456, ...). A stronger signal than \
              cleartext exposure alone — these are guessable without ever \
              capturing the traffic.",
    data_source: &["cred_events (kind = FtpAuth | HttpBasic)"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-521 — Weak Password Requirements",
            url: Some("https://cwe.mitre.org/data/definitions/521.html"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0859 — Valid Accounts",
            url: Some("https://attack.mitre.org/techniques/T0859/"),
        },
    ],
};

enum Match {
    FtpAnonymous,
    HttpBasicWeak,
    HttpBasicEmpty,
}

impl Match {
    fn label(&self) -> &'static str {
        match self {
            Match::FtpAnonymous => "FTP anonymous login",
            Match::HttpBasicWeak => "HTTP Basic — known weak/default password",
            Match::HttpBasicEmpty => "HTTP Basic — empty password",
        }
    }
}

fn classify(event: &CredEvent) -> Option<Match> {
    match event.kind {
        CredKind::FtpAuth => {
            let line = event.note.trim();
            let (cmd, rest) = line.split_once(' ')?;
            if cmd.eq_ignore_ascii_case("USER") && rest.trim().eq_ignore_ascii_case("anonymous") {
                Some(Match::FtpAnonymous)
            } else {
                None
            }
        }
        CredKind::HttpBasic => {
            let line = event.note.trim();
            let token = line.strip_prefix("Authorization: Basic ")?;
            let decoded = decode_base64_lenient(token.trim())?;
            let decoded = String::from_utf8(decoded).ok()?;
            let password = decoded.split_once(':').map(|(_, p)| p)?;
            if password.is_empty() {
                Some(Match::HttpBasicEmpty)
            } else if WEAK_PASSWORDS
                .iter()
                .any(|w| w.eq_ignore_ascii_case(password))
            {
                Some(Match::HttpBasicWeak)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Minimal, tolerant base64 decoder (RFC 4648 standard alphabet). Tolerant
/// because `CredEvent.note` for HTTP Basic is captured via `extract_line`
/// capped at 120 bytes (`observe.rs`), so a long `Authorization` header can
/// be truncated mid-token — a leftover 1-character tail is dropped rather
/// than failing the whole decode. This is a comparison-only decoder (never
/// rendered), so silently under-decoding a truncated tail is an acceptable
/// false-negative, not a correctness risk in the other direction.
fn decode_base64_lenient(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let vals: Vec<u32> = s
        .bytes()
        .take_while(|&b| b != b'=')
        .filter_map(val)
        .collect();
    if vals.is_empty() {
        return None;
    }
    const SHIFTS: [u32; 4] = [18, 12, 6, 0];
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        if chunk.len() < 2 {
            break; // a single leftover char can't decode to anything.
        }
        let n: u32 = chunk
            .iter()
            .zip(SHIFTS.iter())
            .map(|(v, shift)| v << shift)
            .sum();
        let n_bytes = chunk.len() - 1; // 2 chars->1 byte, 3->2 bytes, 4->3 bytes
        for i in 0..n_bytes {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn detect(obs: &Observations) -> Vec<Finding> {
    let mut by_pair: BTreeMap<(IpAddr, IpAddr, u16), Vec<&'static str>> = BTreeMap::new();
    for event in &obs.cred_events {
        if let Some(m) = classify(event) {
            let entry = by_pair
                .entry((event.src, event.dst, event.dst_port))
                .or_default();
            let label = m.label();
            if !entry.contains(&label) {
                entry.push(label);
            }
        }
    }
    if by_pair.is_empty() {
        return Vec::new();
    }

    let evidence: Vec<String> = by_pair
        .iter()
        .take(15)
        .map(|((src, dst, port), labels)| {
            format!(
                "{} -> {}:{} : {}",
                host_label(*src, obs),
                host_label(*dst, obs),
                port,
                labels.join(", ")
            )
        })
        .collect();

    vec![Finding {
        id: "creds.default_or_weak_credentials",
        severity: Severity::Critical,
        title: "Default or trivially-weak credentials observed in cleartext".to_string(),
        summary: format!(
            "{} client\u{2192}server pair(s) used a known default or trivially-weak cleartext \
             credential (FTP anonymous login, or an HTTP Basic password matching a small \
             watchlist of textbook-weak values). More urgent than generic cleartext exposure \u{2014} \
             these are guessable without ever capturing the traffic.",
            by_pair.len()
        ),
        evidence,
        recommendation: "Rotate these credentials immediately to strong, unique values, and move \
                          the protocol off cleartext transport (SFTP/FTPS instead of FTP, HTTPS + \
                          a real auth scheme instead of HTTP Basic) where the device supports it.",
        playbook: vec![
            "These are the highest-priority items among the plaintext-credential findings: a \
             known-default or top-weak-password value can be guessed by an attacker without ever \
             capturing this traffic. Rotate first, investigate second."
                .to_string(),
            "Check vendor documentation for whether the device supports disabling the \
             anonymous/default account entirely rather than just changing its password."
                .to_string(),
        ],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cred_event(kind: CredKind, note: &str) -> CredEvent {
        CredEvent {
            ts: Utc::now(),
            src: ip("10.0.0.5"),
            dst: ip("10.0.0.10"),
            dst_port: 21,
            kind,
            count: 1,
            note: note.to_string(),
        }
    }

    // ---- base64 decoder ----

    #[test]
    fn base64_decodes_a_full_group() {
        // "admin:0000" base64-encoded, no padding needed (10 bytes -> not
        // a multiple of 3, so it DOES need padding: verify anyway).
        let encoded = base64_encode_for_test(b"admin:0000");
        assert_eq!(decode_base64_lenient(&encoded).unwrap(), b"admin:0000");
    }

    #[test]
    fn base64_tolerates_a_truncated_trailing_char() {
        let encoded = base64_encode_for_test(b"admin:0000");
        let truncated = &encoded[..encoded.len() - 1];
        // Must not panic; either decodes a shorter-but-correct prefix or
        // returns fewer bytes — never garbage that would falsely match.
        let _ = decode_base64_lenient(truncated);
    }

    #[test]
    fn base64_rejects_input_with_no_valid_characters() {
        // '!' and '=' are the only bytes here — '=' halts scanning
        // immediately (treated as padding) and '!' isn't in the alphabet,
        // so nothing decodable remains.
        assert!(decode_base64_lenient("!!!=!!!").is_none());
    }

    #[test]
    fn base64_skips_non_alphabet_bytes_rather_than_erroring() {
        // Lenient by design: non-alphabet bytes are dropped, not treated as
        // a hard parse error. A single leftover char after dropping is
        // still correctly refused (can't decode to a full byte).
        let _ = decode_base64_lenient("a!b!c");
    }

    /// Minimal reference encoder used only by these tests (production code
    /// never needs to encode).
    fn base64_encode_for_test(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
            out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6 & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    // ---- classify ----

    #[test]
    fn ftp_anonymous_matches() {
        let e = cred_event(CredKind::FtpAuth, "USER anonymous");
        assert!(matches!(classify(&e), Some(Match::FtpAnonymous)));
    }

    #[test]
    fn ftp_named_user_does_not_match() {
        let e = cred_event(CredKind::FtpAuth, "USER engineer1");
        assert!(classify(&e).is_none());
    }

    #[test]
    fn http_basic_weak_password_matches() {
        let token = base64_encode_for_test(b"admin:password");
        let e = cred_event(
            CredKind::HttpBasic,
            &format!("Authorization: Basic {token}"),
        );
        assert!(matches!(classify(&e), Some(Match::HttpBasicWeak)));
    }

    #[test]
    fn http_basic_empty_password_matches() {
        let token = base64_encode_for_test(b"admin:");
        let e = cred_event(
            CredKind::HttpBasic,
            &format!("Authorization: Basic {token}"),
        );
        assert!(matches!(classify(&e), Some(Match::HttpBasicEmpty)));
    }

    #[test]
    fn http_basic_strong_password_does_not_match() {
        let token = base64_encode_for_test(b"admin:Xk9$mQ2!vP7z");
        let e = cred_event(
            CredKind::HttpBasic,
            &format!("Authorization: Basic {token}"),
        );
        assert!(classify(&e).is_none());
    }

    #[test]
    fn telnet_and_snmp_never_match() {
        assert!(classify(&cred_event(
            CredKind::TelnetSession,
            "Telnet session (cleartext)"
        ))
        .is_none());
        assert!(classify(&cred_event(CredKind::Snmpv1v2c, "community: public")).is_none());
    }

    // ---- detect() wiring + evidence shape ----

    #[test]
    fn detect_fires_and_groups_by_pair() {
        let mut obs = Observations::default();
        obs.cred_events
            .push(cred_event(CredKind::FtpAuth, "USER anonymous"));
        let findings = detect(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "creds.default_or_weak_credentials");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].evidence.len(), 1);
        assert!(findings[0].evidence[0].contains("FTP anonymous login"));
    }

    #[test]
    fn detect_silent_when_nothing_matches() {
        let mut obs = Observations::default();
        obs.cred_events
            .push(cred_event(CredKind::FtpAuth, "USER engineer1"));
        assert!(detect(&obs).is_empty());
    }

    /// The load-bearing privacy test: `CredEvent.note` (which may contain a
    /// real, non-default username or password) must never appear verbatim
    /// in the finding's evidence — only the derived category label.
    #[test]
    fn evidence_never_contains_raw_note_content() {
        let mut obs = Observations::default();
        // "123456" is on the watchlist but shares no substring with the
        // category label text below, so this test can't pass by accident.
        let token = base64_encode_for_test(b"REAL-ENGINEER-NAME:123456");
        obs.cred_events.push(cred_event(
            CredKind::HttpBasic,
            &format!("Authorization: Basic {token}"),
        ));
        let findings = detect(&obs);
        assert_eq!(findings.len(), 1);
        let ev = &findings[0].evidence[0];
        assert!(!ev.contains("REAL-ENGINEER-NAME"));
        assert!(!ev.contains(&token));
        assert!(
            !ev.contains("123456"),
            "must not echo the matched password value itself"
        );
        assert!(ev.contains("known weak/default password"));
    }
}
