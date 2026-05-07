use std::collections::BTreeMap;

use crate::observe::{CredKind, Observations};

use super::{Finding, Severity};

pub fn detect(obs: &Observations) -> Vec<Finding> {
    if obs.cred_events.is_empty() {
        return Vec::new();
    }

    // Group by (kind, dst) so the report doesn't list 50,000 individual
    // Telnet packets — one finding per service.
    let mut groups: BTreeMap<(CredKind, std::net::IpAddr, u16), Vec<&str>> = BTreeMap::new();
    let mut counts: BTreeMap<(CredKind, std::net::IpAddr, u16), usize> = BTreeMap::new();

    for ev in &obs.cred_events {
        let key = (ev.kind, ev.dst, ev.dst_port);
        *counts.entry(key).or_insert(0) += 1;
        let bucket = groups.entry(key).or_default();
        if bucket.len() < 5 {
            bucket.push(ev.note.as_str());
        }
    }

    groups
        .into_iter()
        .map(|((kind, dst, port), examples)| {
            let total = counts[&(kind, dst, port)];
            let (id, title, recommendation) = match kind {
                CredKind::FtpAuth => (
                    "creds.ftp",
                    "Plaintext FTP authentication observed",
                    "Replace FTP with SFTP/FTPS, or restrict to a management VLAN. Rotate any credentials seen on the wire — assume compromised.",
                ),
                CredKind::TelnetSession => (
                    "creds.telnet",
                    "Telnet session observed (cleartext by definition)",
                    "Migrate the device to SSH if supported, or place behind a jump host. Rotate any passwords used during the session window.",
                ),
                CredKind::HttpBasic => (
                    "creds.http_basic",
                    "HTTP Basic authentication over plaintext HTTP",
                    "Move the service behind TLS (HTTPS) or restrict to an isolated mgmt network. Rotate exposed credentials.",
                ),
                CredKind::Snmpv1v2c => (
                    "creds.snmp",
                    "SNMPv1/v2c traffic (plaintext community strings)",
                    "Migrate to SNMPv3 with auth+priv, or restrict polling to a hardened mgmt VLAN. Rotate community strings — they pass in the clear.",
                ),
            };
            let summary = format!(
                "{total} {} packet(s) seen to {dst}:{port}. Credentials traversing this flow should be considered exposed.",
                kind_label(kind)
            );
            Finding {
                id,
                severity: Severity::Critical,
                title: title.to_string(),
                summary,
                evidence: examples.iter().map(|s| s.to_string()).collect(),
                recommendation,
            }
        })
        .collect()
}

fn kind_label(k: CredKind) -> &'static str {
    match k {
        CredKind::FtpAuth => "FTP auth",
        CredKind::TelnetSession => "Telnet",
        CredKind::HttpBasic => "HTTP Basic",
        CredKind::Snmpv1v2c => "SNMPv1/v2c",
    }
}
