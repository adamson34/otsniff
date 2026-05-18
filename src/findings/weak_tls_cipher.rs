//! S-2.07: `compat.weak_tls_cipher` — TLS ClientHello with RC4/DES/3DES/NULL.
//!
//! Fires at severity Medium when a ClientHello advertises one or more of the
//! following cipher suite codes (AC-002, BC-3.04.005):
//!
//! | Code   | Name                                |
//! |--------|-------------------------------------|
//! | 0x0001 | TLS_RSA_WITH_NULL_MD5               |
//! | 0x0002 | TLS_RSA_WITH_NULL_SHA               |
//! | 0x0004 | TLS_RSA_WITH_RC4_128_MD5            |
//! | 0x0005 | TLS_RSA_WITH_RC4_128_SHA            |
//! | 0x0009 | TLS_RSA_WITH_DES_CBC_SHA            |
//! | 0x000A | TLS_RSA_WITH_3DES_EDE_CBC_SHA       |
//!
//! GREASE values (EC-001) — 0xXAXA pattern — are intentionally ignored.
//! The detector is a sibling to `compat.stale_tls` and they fire
//! independently (AC-003).

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const WEAK_TLS_CIPHER_METADATA: RuleMetadata = RuleMetadata {
    id: "compat.weak_tls_cipher",
    title: "Weak TLS cipher suites advertised (RC4 / DES / 3DES / NULL)",
    severity: Severity::Medium,
    trigger: "Fires when a TLS ClientHello on TCP/443 or TCP/8443 includes any of the \
              following cipher suite codes: 0x0001 (NULL_MD5), 0x0002 (NULL_SHA), \
              0x0004 (RC4_128_MD5), 0x0005 (RC4_128_SHA), 0x0009 (DES_CBC_SHA), \
              0x000A (3DES_EDE_CBC_SHA). These suites are broken or severely \
              weakened — RC4 has statistical biases exploitable in practice \
              (RFC 7465), DES has a 56-bit key vulnerable to brute force, 3DES \
              is vulnerable to Sweet32 (CVE-2016-2183), and NULL suites provide \
              no encryption at all. Detection runs on the cipher_suites list in \
              the TLS ClientHello handshake message regardless of which suite the \
              server ultimately negotiates. GREASE values (RFC 8701) are \
              skipped.",
    data_source: &["tls_cipher_suites"],
    references: &[
        Reference {
            kind: ReferenceKind::Rfc,
            label: "RFC 7465 — Prohibiting RC4 Cipher Suites",
            url: Some("https://datatracker.ietf.org/doc/html/rfc7465"),
        },
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-326 — Inadequate Encryption Strength",
            url: Some("https://cwe.mitre.org/data/definitions/326.html"),
        },
    ],
};

/// Cipher suite codes considered weak (BC-3.04.005, AC-002).
const WEAK_CIPHERS: &[u16] = &[
    0x0001, // TLS_RSA_WITH_NULL_MD5
    0x0002, // TLS_RSA_WITH_NULL_SHA
    0x0004, // TLS_RSA_WITH_RC4_128_MD5
    0x0005, // TLS_RSA_WITH_RC4_128_SHA
    0x0009, // TLS_RSA_WITH_DES_CBC_SHA
    0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
];

fn is_weak(code: u16) -> bool {
    WEAK_CIPHERS.contains(&code)
}

fn cipher_name(code: u16) -> &'static str {
    match code {
        0x0001 => "TLS_RSA_WITH_NULL_MD5",
        0x0002 => "TLS_RSA_WITH_NULL_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0009 => "TLS_RSA_WITH_DES_CBC_SHA",
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        _ => "unknown",
    }
}

/// BC-3.04.005 (S-2.07): emit one finding per distinct (src, dst) pair that
/// advertised at least one weak cipher suite. Rolls up all dst_ports for the
/// same pair into a single finding. GREASE values (EC-001) are skipped because
/// they are not in `WEAK_CIPHERS`.
pub fn build_findings(obs: &Observations) -> Vec<Finding> {
    // Accumulate weak codes by (src, dst). BTreeMap for deterministic order.
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), BTreeMap<u16, ()>> = BTreeMap::new();

    for ((src, dst, _dst_port), suites) in &obs.tls_cipher_suites {
        let weak: Vec<u16> = suites.iter().copied().filter(|&c| is_weak(c)).collect();
        if weak.is_empty() {
            continue;
        }
        let codes = by_pair.entry((*src, *dst)).or_default();
        for c in weak {
            codes.insert(c, ());
        }
    }

    if by_pair.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for ((src, dst), weak_codes) in by_pair {
        let codes_vec: Vec<u16> = weak_codes.keys().copied().collect();
        let code_list: Vec<String> = codes_vec
            .iter()
            .take(5)
            .map(|&c| format!("0x{c:04X} ({})", cipher_name(c)))
            .collect();

        let summary = format!(
            "ClientHello from {} to {} advertises {} weak cipher suite(s): {}. \
             These suites are broken or severely weakened (RC4 has known biases, \
             DES uses a 56-bit key, 3DES is vulnerable to Sweet32, NULL suites \
             provide no encryption). Even if the server rejects them, advertising \
             these suites indicates a legacy or misconfigured TLS stack.",
            host_label(src, obs),
            host_label(dst, obs),
            codes_vec.len(),
            code_list.join(", "),
        );

        let evidence = codes_vec
            .iter()
            .take(5)
            .map(|&c| {
                format!(
                    "{} -> {} : 0x{c:04X} ({})",
                    host_label(src, obs),
                    host_label(dst, obs),
                    cipher_name(c)
                )
            })
            .collect();

        let playbook = vec![
            format!(
                "Identify the TLS client at {} and audit its cipher suite configuration. \
                 A client advertising RC4, DES, 3DES, or NULL suites typically has a legacy \
                 TLS library (OpenSSL < 1.1.0, Java < 8u161) or explicit low-security \
                 policy overrides.",
                host_label(src, obs)
            ),
            "Remove the weak suites from the client's cipher suite list. In OpenSSL, \
             set `ssl_ciphers = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:...` \
             (no RC4, no DES, no NULL, no EXPORT, no LOW). In Java, use `jdk.tls.disabledAlgorithms` \
             to exclude RC4, DES, DESede, and NULL."
                .to_string(),
            "If the client is an OT device whose firmware cannot be updated, consider \
             placing it behind a TLS-terminating proxy that enforces a strong cipher policy \
             on the LAN side while negotiating only modern suites with the server."
                .to_string(),
            "Verify the affected server is not also accepting these suites. Run \
             `openssl s_client -connect <host>:443 -cipher RC4 -tls1_2` and check \
             whether the handshake succeeds — if it does, the server must also be hardened."
                .to_string(),
        ];

        findings.push(Finding {
            id: "compat.weak_tls_cipher",
            severity: Severity::Medium,
            title: format!(
                "Weak TLS cipher suites advertised by {} (RC4 / DES / 3DES / NULL)",
                host_label(src, obs)
            ),
            summary,
            evidence,
            recommendation: "Remove RC4, DES, 3DES, and NULL cipher suites from the client TLS \
                             configuration. These suites are broken or severely weakened; their \
                             presence indicates a legacy or misconfigured TLS stack.",
            playbook,
        });
    }

    findings
}
