use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::{CredEvent, CredKind, Observations};

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const FTP_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.ftp",
    title: "Plaintext FTP authentication observed",
    severity: Severity::Critical,
    trigger: "Fires when at least one TCP/21 packet starts with `USER ` \
              or `PASS ` (case-insensitive). FTP transmits credentials \
              and data in cleartext; any host on a SPAN-port of the \
              same VLAN can capture them.",
    data_source: &["cred_events (kind = FtpAuth)"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-319 — Cleartext Transmission of Sensitive Information",
            url: Some("https://cwe.mitre.org/data/definitions/319.html"),
        },
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 959 — File Transfer Protocol",
            url: Some("https://datatracker.ietf.org/doc/html/rfc959"),
        },
    ],
};

pub const TELNET_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.telnet",
    title: "Telnet session observed (cleartext by definition)",
    severity: Severity::Critical,
    trigger: "Fires when any non-empty payload is observed on TCP/23 \
              (src or dst). Telnet has no encryption — every byte of \
              the session including the login is in cleartext, so we \
              don't try to identify the authentication exchange \
              specifically.",
    data_source: &["cred_events (kind = TelnetSession)"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-319 — Cleartext Transmission of Sensitive Information",
            url: Some("https://cwe.mitre.org/data/definitions/319.html"),
        },
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 854 — Telnet Protocol Specification",
            url: Some("https://datatracker.ietf.org/doc/html/rfc854"),
        },
    ],
};

pub const HTTP_BASIC_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.http_basic",
    title: "HTTP Basic authentication over plaintext HTTP",
    severity: Severity::Critical,
    trigger: "Fires when a packet on TCP/80 or TCP/8080 contains the \
              substring `Authorization: Basic `. HTTP Basic encodes the \
              username:password with base64 (not encryption); over \
              cleartext HTTP it is trivially decoded by anyone reading \
              the wire.",
    data_source: &["cred_events (kind = HttpBasic)"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-319 — Cleartext Transmission of Sensitive Information",
            url: Some("https://cwe.mitre.org/data/definitions/319.html"),
        },
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 7617 — The 'Basic' HTTP Authentication Scheme",
            url: Some("https://datatracker.ietf.org/doc/html/rfc7617"),
        },
    ],
};

pub const SNMP_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.snmp",
    title: "SNMPv1 / SNMPv2c traffic (plaintext community strings)",
    severity: Severity::Critical,
    trigger: "Fires when a UDP/161 or UDP/162 packet looks like an SNMP \
              message — BER SEQUENCE tag (0x30) at offset 0, followed \
              by an INTEGER (0x02 0x01) version tag with value 0 (v1) \
              or 1 (v2c). The community string in v1/v2c is the only \
              auth credential and passes in the clear.",
    data_source: &["cred_events (kind = Snmpv1v2c)"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-319 — Cleartext Transmission of Sensitive Information",
            url: Some("https://cwe.mitre.org/data/definitions/319.html"),
        },
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 3411 — Architecture for SNMPv3 (the secure replacement)",
            url: Some("https://datatracker.ietf.org/doc/html/rfc3411"),
        },
    ],
};

/// Detect plaintext-credentials traffic. Produces one `Finding` per
/// `CredKind` (Telnet, FTP, HTTP-Basic, SNMPv1/v2c), regardless of how
/// many destinations carry that kind of traffic. Destinations are
/// surfaced as evidence, not as separate findings — see
/// `docs/specs/finding-dedup.md`.
pub fn detect(obs: &Observations) -> Vec<Finding> {
    if obs.cred_events.is_empty() {
        return Vec::new();
    }

    let mut by_kind: BTreeMap<CredKind, Vec<&CredEvent>> = BTreeMap::new();
    for ev in &obs.cred_events {
        by_kind.entry(ev.kind).or_default().push(ev);
    }

    by_kind
        .into_iter()
        .map(|(kind, events)| build_finding(kind, &events, obs))
        .collect()
}

fn build_finding(kind: CredKind, events: &[&CredEvent], obs: &Observations) -> Finding {
    // Aggregate per (dst, port) — one evidence line per destination,
    // sorted by packet count descending so the noisiest hosts are
    // listed first.
    let mut packets_per_dst: BTreeMap<(IpAddr, u16), u64> = BTreeMap::new();
    for ev in events {
        *packets_per_dst.entry((ev.dst, ev.dst_port)).or_insert(0) += 1;
    }
    let total_packets = events.len();
    let host_count = packets_per_dst.len();

    let mut sorted_dsts: Vec<((IpAddr, u16), u64)> = packets_per_dst.into_iter().collect();
    sorted_dsts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    let evidence: Vec<String> = sorted_dsts
        .iter()
        .take(15)
        .map(|((dst, port), n)| format!("{}:{port} ({n} packet(s))", host_label(*dst, obs)))
        .collect();

    let (id, title, recommendation) = match kind {
        CredKind::FtpAuth => (
            "creds.ftp",
            "Plaintext FTP authentication observed",
            "Replace FTP with SFTP/FTPS, or restrict to a management VLAN. Rotate any credentials seen on the wire — assume compromised.",
        ),
        CredKind::TelnetSession => (
            "creds.telnet",
            "Telnet session observed (cleartext by definition)",
            "Migrate the device(s) to SSH if supported, or place behind a jump host. Rotate any passwords used during the session window.",
        ),
        CredKind::HttpBasic => (
            "creds.http_basic",
            "HTTP Basic authentication over plaintext HTTP",
            "Move the service(s) behind TLS (HTTPS) or restrict to an isolated mgmt network. Rotate exposed credentials.",
        ),
        CredKind::Snmpv1v2c => (
            "creds.snmp",
            "SNMPv1/v2c traffic (plaintext community strings)",
            "Migrate to SNMPv3 with auth+priv, or restrict polling to a hardened mgmt VLAN. Rotate community strings — they pass in the clear.",
        ),
    };

    let summary = format!(
        "{} {} packet(s) seen across {} host(s). Credentials traversing these flows should be considered exposed.",
        total_packets,
        kind_label(kind),
        host_count
    );

    let dst_list = format_dst_list(&sorted_dsts);
    let secure_alt = match kind {
        CredKind::FtpAuth => "SFTP / FTPS",
        CredKind::TelnetSession => "SSH",
        CredKind::HttpBasic => "HTTPS (TLS)",
        CredKind::Snmpv1v2c => "SNMPv3 with auth+priv",
    };
    let kind_phrase = kind_label(kind);
    let mut playbook = vec![
        format!(
            "Treat any password used during the {kind_phrase} sessions to {dst_list} as exposed. \
             Plan a rotation with the on-shift engineer for those devices and any account whose \
             credentials may be reused (a Telnet password on a switch is often the same engineer \
             account used elsewhere)."
        ),
        format!(
            "Migrate the listed devices to {secure_alt} where they support it. The asset \
             inventory shows which hosts also speak the secure equivalent — use that as the \
             starting list."
        ),
        format!(
            "For devices without a secure alternative (older Moxa serial servers, legacy HMIs, \
             managed switches that only support {kind_phrase}), place behind a jump host on a \
             hardened management VLAN. Document the exception with a revocation date."
        ),
        format!(
            "Record the credentials-exposed window in the change log so future investigations \
             know which sessions to consider compromised. Capture window: see report header."
        ),
    ];
    if matches!(kind, CredKind::Snmpv1v2c) {
        playbook.insert(
            1,
            "Rotate the community strings — they pass in the clear and any host on a span port \
             of the same VLAN can read them."
                .to_string(),
        );
    }

    Finding {
        id,
        severity: Severity::Critical,
        title: title.to_string(),
        summary,
        evidence,
        recommendation,
        playbook,
    }
}

fn format_dst_list(sorted_dsts: &[((IpAddr, u16), u64)]) -> String {
    if sorted_dsts.is_empty() {
        return "the listed hosts".to_string();
    }
    if sorted_dsts.len() == 1 {
        return format!("`{}:{}`", sorted_dsts[0].0 .0, sorted_dsts[0].0 .1);
    }
    if sorted_dsts.len() <= 3 {
        let parts: Vec<String> = sorted_dsts
            .iter()
            .map(|((ip, port), _)| format!("`{ip}:{port}`"))
            .collect();
        return parts.join(", ");
    }
    format!(
        "`{}:{}` and {} other host(s)",
        sorted_dsts[0].0 .0,
        sorted_dsts[0].0 .1,
        sorted_dsts.len() - 1
    )
}

fn kind_label(k: CredKind) -> &'static str {
    match k {
        CredKind::FtpAuth => "FTP auth",
        CredKind::TelnetSession => "Telnet",
        CredKind::HttpBasic => "HTTP Basic",
        CredKind::Snmpv1v2c => "SNMPv1/v2c",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{CredEvent, CredKind, Observations};
    use chrono::TimeZone;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap()
    }

    fn telnet_event(dst: &str) -> CredEvent {
        CredEvent {
            ts: ts(),
            src: ip("10.0.0.1"),
            dst: ip(dst),
            dst_port: 23,
            kind: CredKind::TelnetSession,
            count: 1,
            note: "Telnet session (cleartext)".to_string(),
        }
    }

    #[test]
    fn rolls_up_one_finding_per_kind_across_many_hosts() {
        // 12 distinct telnet destinations, multiple events each.
        let mut events = Vec::new();
        for i in 1..=12u8 {
            // 5 packets per host, varying count to test sort order
            for _ in 0..(13 - i) {
                events.push(telnet_event(&format!("192.168.1.{i}")));
            }
        }
        let obs = Observations {
            cred_events: events,
            ..Default::default()
        };
        let findings = detect(&obs);
        assert_eq!(findings.len(), 1, "must roll up to one finding per kind");
        let f = &findings[0];
        assert_eq!(f.id, "creds.telnet");
        assert!(f.summary.contains("12 host(s)"));
        // Evidence sorted by packet count desc — host .1 should appear
        // first (12 packets) and host .12 last (1 packet).
        let first_evidence = &f.evidence[0];
        assert!(
            first_evidence.starts_with("192.168.1.1:23"),
            "expected most-packets-first ordering; got: {first_evidence}"
        );
    }

    #[test]
    fn distinct_kinds_produce_distinct_findings() {
        let obs = Observations {
            cred_events: vec![
                telnet_event("10.0.0.5"),
                CredEvent {
                    ts: ts(),
                    src: ip("10.0.0.1"),
                    dst: ip("10.0.0.5"),
                    dst_port: 21,
                    kind: CredKind::FtpAuth,
                    count: 1,
                    note: "USER admin".to_string(),
                },
            ],
            ..Default::default()
        };
        let findings = detect(&obs);
        assert_eq!(findings.len(), 2);
        let ids: Vec<_> = findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"creds.telnet"));
        assert!(ids.contains(&"creds.ftp"));
    }

    #[test]
    fn empty_input_produces_no_findings() {
        let obs = Observations::default();
        assert!(detect(&obs).is_empty());
    }

    #[test]
    fn evidence_capped_at_15_destinations() {
        // 30 distinct destinations, one event each.
        let events: Vec<CredEvent> = (1..=30u8)
            .map(|i| telnet_event(&format!("10.0.0.{i}")))
            .collect();
        let obs = Observations {
            cred_events: events,
            ..Default::default()
        };
        let findings = detect(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), 15);
        // Summary still reports the full count even though evidence is capped.
        assert!(findings[0].summary.contains("30 host(s)"));
    }
}
