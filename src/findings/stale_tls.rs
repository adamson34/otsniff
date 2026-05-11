use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "compat.stale_tls",
    title: "Deprecated TLS versions observed (SSL 3.0 / TLS 1.0 / 1.1)",
    severity: Severity::Medium,
    trigger: "Fires when a TLS ClientHello on TCP/443 or TCP/8443 \
              carries a `legacy_version` field of 0x0300 (SSL 3.0), \
              0x0301 (TLS 1.0), or 0x0302 (TLS 1.1). Detection runs on \
              the TLS record + handshake layout (content_type 0x16, \
              handshake type 0x01) — no full TLS state machine. These \
              versions are deprecated and blocked by default in modern \
              Windows / browsers; their presence indicates legacy \
              clients (older Java, embedded devices) or legacy \
              services.",
    data_source: &["tls_client_hellos"],
    references: &[
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
            url: Some("https://datatracker.ietf.org/doc/html/rfc8996"),
        },
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-326 — Inadequate Encryption Strength",
            url: Some("https://cwe.mitre.org/data/definitions/326.html"),
        },
    ],
};

/// Versions we consider stale: SSL 3.0, TLS 1.0, TLS 1.1.
/// 0x0303 (TLS 1.2) and 0x0304 (TLS 1.3) pass.
fn is_stale(version: u16) -> bool {
    matches!(version, 0x0300..=0x0302)
}

fn version_label(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

pub fn detect(obs: &Observations) -> Vec<Finding> {
    let stale: Vec<((IpAddr, IpAddr, u16, u16), u64)> = obs
        .tls_client_hellos
        .iter()
        .filter(|((_, _, _, ver), _)| is_stale(*ver))
        .map(|(k, v)| (*k, *v))
        .collect();

    if stale.is_empty() {
        return Vec::new();
    }

    let total_hellos: u64 = stale.iter().map(|(_, n)| n).sum();
    let pair_count = stale.len();
    let mut by_version: BTreeMap<u16, u64> = BTreeMap::new();
    for ((_, _, _, ver), n) in &stale {
        *by_version.entry(*ver).or_insert(0) += n;
    }

    let mut sorted = stale.clone();
    sorted.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    let evidence: Vec<String> = sorted
        .iter()
        .take(15)
        .map(|((src, dst, port, ver), n)| {
            format!(
                "{src} -> {dst}:{port} : {} ({n} hello(s))",
                version_label(*ver)
            )
        })
        .collect();

    let version_summary: Vec<String> = by_version
        .iter()
        .map(|(ver, n)| format!("{} ({n} hello(s))", version_label(*ver)))
        .collect();

    let summary = format!(
        "{total_hellos} ClientHello(s) using deprecated TLS versions seen across \
         {pair_count} host pair(s): {}. These versions are deprecated and blocked by default \
         in modern Windows / browsers. Their presence indicates legacy clients (older Java \
         runtimes, embedded devices) or legacy services.",
        version_summary.join(", ")
    );

    let distinct_clients: std::collections::BTreeSet<IpAddr> =
        sorted.iter().map(|((s, _, _, _), _)| *s).collect();
    let client_list = format_host_list(&distinct_clients);

    let playbook = vec![
        format!(
            "Identify the source hosts and the services they're connecting to: {client_list}. \
             A legacy TLS ClientHello almost always traces to one of: an older Java runtime, \
             a Windows host with TLS 1.0/1.1 still enabled in Schannel, or an embedded device \
             whose firmware predates TLS 1.2."
        ),
        "For Windows clients: confirm TLS 1.2+ is enabled and TLS 1.0 / TLS 1.1 / SSL 3.0 are \
         disabled in Schannel registry settings (HKLM\\SYSTEM\\CurrentControlSet\\Control\\\
         SecurityProviders\\SCHANNEL\\Protocols). Microsoft has a tested registry script for \
         this — use that, don't hand-edit."
            .to_string(),
        "For services / servers: upgrade the TLS implementation. If it's an embedded device \
         that only supports TLS 1.0 (older Moxa, older Schneider HMIs), put it behind a \
         TLS-terminating reverse proxy that speaks modern TLS to clients."
            .to_string(),
        "Treat any captured authentication traffic from these connections as suspect — cipher \
         suites available with TLS 1.0/1.1 are vulnerable to known attacks (BEAST, POODLE, \
         downgrade-to-RC4). Rotate any credentials or session tokens that crossed these flows."
            .to_string(),
        "Audit the firewall ruleset for outbound TLS to legacy services on OT — the modern \
         answer is \"only allow tcp/443 to a known set of update servers and vendor cloud \
         endpoints, all of which speak TLS 1.2+.\""
            .to_string(),
    ];

    vec![Finding {
        id: "compat.stale_tls",
        severity: Severity::Medium,
        title: "Deprecated TLS versions observed (SSL 3.0 / TLS 1.0 / 1.1)".to_string(),
        summary,
        evidence,
        recommendation: "Identify the source clients and services. Modern Windows blocks TLS 1.0/1.1 by default; their presence indicates legacy clients (older Java, embedded devices) or services worth replacing. Cipher suites available at these versions are vulnerable to BEAST / POODLE / downgrade attacks.",
        playbook,
    }]
}

fn format_host_list(hosts: &std::collections::BTreeSet<IpAddr>) -> String {
    let v: Vec<IpAddr> = hosts.iter().copied().collect();
    match v.len() {
        0 => "the listed hosts".to_string(),
        1 => format!("`{}`", v[0]),
        2 => format!("`{}` and `{}`", v[0], v[1]),
        n if n <= 4 => v
            .iter()
            .map(|ip| format!("`{ip}`"))
            .collect::<Vec<_>>()
            .join(", "),
        _ => format!("`{}` and {} other host(s)", v[0], v.len() - 1),
    }
}
