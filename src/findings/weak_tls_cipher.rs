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

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const WEAK_TLS_CIPHER_METADATA: RuleMetadata = RuleMetadata {
    id: "compat.weak_tls_cipher",
    title: "Weak TLS cipher suites advertised (RC4 / DES / 3DES / NULL)",
    severity: Severity::Medium,
    trigger: "S-2.07: TBD by implementer",
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

/// S-2.07 stub: returns empty Vec so existing snapshot tests stay green.
/// Real detector logic lands in Step 4 (implementation).
///
/// Self-check (BC-5.38.005 invariant 1): "If I include this real
/// implementation, will the test for this function pass trivially without
/// any implementer work?" — No real implementation is included; this is
/// a GREEN-BY-DESIGN stub body (zero branching, no I/O, no helpers,
/// 1 line) whose result (`Vec::new()`) is correct at stub time because
/// `tls_cipher_suites` is always empty until the observer extension lands.
pub fn build_findings(_obs: &Observations) -> Vec<Finding> {
    Vec::new()
}
