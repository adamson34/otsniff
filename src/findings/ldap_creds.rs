use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const LDAP_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.ldap_simple_bind",
    title: "LDAP plaintext simple-bind observed",
    severity: Severity::Critical,
    trigger: "Fires when at least one LDAPv3 BindRequest with SimpleAuthentication \
              (tag 0x80) is observed on tcp/389 or tcp/3268 without a prior successful \
              STARTTLS exchange on the same flow. The username and password are \
              transmitted in cleartext; any host on a SPAN port of the same VLAN can \
              capture them. Anonymous binds (empty DN + empty password) are not \
              flagged — they carry no credential.",
    data_source: &["ldap_bind_events"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-319 — Cleartext Transmission of Sensitive Information",
            url: Some("https://cwe.mitre.org/data/definitions/319.html"),
        },
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 4511 — Lightweight Directory Access Protocol (LDAP): The Protocol",
            url: Some("https://datatracker.ietf.org/doc/html/rfc4511"),
        },
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 4513 — LDAP Authentication Methods and Security Mechanisms (STARTTLS)",
            url: Some("https://datatracker.ietf.org/doc/html/rfc4513"),
        },
    ],
};

/// Detect LDAP plaintext simple-bind traffic.
///
/// Fires `creds.ldap_simple_bind` at severity Critical for each `LdapBindEvent`
/// where `used_starttls` is `false` and `anonymous` is `false`. Events are
/// rolled up by `(src, dst)` like the other `creds.*` findings.
///
/// AC-003: binds preceded by a successful STARTTLS exchange (`used_starttls ==
/// true`) are suppressed — the finding does NOT fire.
/// EC-003: anonymous binds (`anonymous == true`) are suppressed.
///
/// See S-2.05 for the full acceptance criteria and edge-case table.
pub fn build_findings(obs: &Observations) -> Vec<Finding> {
    // Filter to plaintext, non-anonymous binds only.
    let plaintext_events: Vec<_> = obs
        .ldap_bind_events
        .iter()
        .filter(|ev| !ev.used_starttls && !ev.anonymous)
        .collect();

    if plaintext_events.is_empty() {
        return Vec::new();
    }

    // Roll up by (src, dst) — same dedup logic as the other creds.* finders.
    // Use BTreeMap for deterministic iteration (required for stable reports).
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<u16>> = BTreeMap::new();
    for ev in &plaintext_events {
        by_pair
            .entry((ev.src, ev.dst))
            .or_default()
            .push(ev.dst_port);
    }

    let pair_count = by_pair.len();
    let event_count = plaintext_events.len();

    // Build evidence lines: "src_label -> dst_label:port" per unique pair.
    // F-ADV-P1-003: use ASCII `->` so the diff key extractor can parse the line.
    // Cap at 5 evidence samples to match story guidance.
    let evidence: Vec<String> = by_pair
        .iter()
        .take(5)
        .map(|((src, dst), ports)| {
            let mut unique_ports: Vec<u16> = {
                let mut p = ports.clone();
                p.sort_unstable();
                p.dedup();
                p
            };
            unique_ports.sort_unstable();
            let port_str = unique_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            // F-ADV-P1-003: use ASCII `->` so the diff key extractors
            // (src/diff.rs:166-179) can parse src/dst pseudonyms from the
            // evidence line. The other engineering-class detectors emit `->`;
            // this matches them.
            format!(
                "{} -> {}:{}",
                host_label(*src, obs),
                host_label(*dst, obs),
                port_str
            )
        })
        .collect();

    let summary = format!(
        "{event_count} plaintext LDAP simple-bind(s) observed across {pair_count} source/destination pair(s). \
         Credentials transmitted in cleartext — treat as exposed.",
    );

    vec![Finding {
        id: "creds.ldap_simple_bind",
        severity: Severity::Critical,
        title: "LDAP plaintext simple-bind observed".to_string(),
        summary,
        evidence,
        recommendation: "Enable LDAPS (tcp/636) or enforce STARTTLS before bind. \
                         Rotate any credentials seen on the wire — assume compromised.",
        playbook: vec![
            "Treat any password used in the flagged LDAP bind(s) as exposed. \
             Plan a rotation with the on-shift engineer for the corresponding \
             Active Directory or LDAP accounts, including any service accounts \
             that may share the same credentials."
                .to_string(),
            "Migrate directory clients and servers to LDAPS (tcp/636) or \
             require STARTTLS on tcp/389 before authentication. \
             Enforce the policy at the firewall level — block plaintext tcp/389 \
             binds from reaching directory servers unless STARTTLS is confirmed."
                .to_string(),
            "For legacy clients that cannot negotiate STARTTLS, place them behind \
             a jump host on a hardened management VLAN and document the exception \
             with a revocation date."
                .to_string(),
            "Record the credentials-exposed window in the change log so future \
             investigations know which sessions to treat as compromised. \
             Capture window: see report header."
                .to_string(),
        ],
    }]
}
