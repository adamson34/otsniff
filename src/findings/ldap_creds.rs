use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const LDAP_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.ldap_simple_bind",
    title: "S-2.05: TBD by implementer",
    severity: Severity::Critical,
    trigger: "S-2.05: TBD by implementer",
    data_source: &["ldap_bind_events"],
    references: &[Reference {
        kind: ReferenceKind::Cwe,
        label: "CWE-319 — Cleartext Transmission of Sensitive Information",
        url: Some("https://cwe.mitre.org/data/definitions/319.html"),
    }],
};

/// Detect LDAP plaintext simple-bind traffic.
///
/// Fires `creds.ldap_simple_bind` at severity Critical for each `LdapBindEvent`
/// where `used_starttls` is `false` and `anonymous` is `false`. Events are
/// rolled up by `(src, dst)` like the other `creds.*` findings.
///
/// AC-003: binds preceded by a successful STARTTLS exchange (`used_starttls ==
/// true`) are suppressed — the finding does NOT fire.
///
/// See S-2.05 for the full acceptance criteria and edge-case table.
pub fn build_findings(_obs: &Observations) -> Vec<Finding> {
    todo!("S-2.05: LDAP creds detector landing in step 4")
}
