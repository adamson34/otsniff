use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const NTLM_METADATA: RuleMetadata = RuleMetadata {
    id: "compat.ntlmv1",
    title: "NTLMv1 authentication observed",
    severity: Severity::High,
    trigger: "S-2.06: TBD by implementer",
    data_source: &["ntlm_events"],
    references: &[
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-916 — Use of Password Hash With Insufficient Computational Effort",
            url: Some("https://cwe.mitre.org/data/definitions/916.html"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0859 — Valid Accounts",
            url: Some("https://attack.mitre.org/techniques/T0859/"),
        },
    ],
};

/// S-2.06 stub: returns empty Vec so existing snapshot tests continue to pass.
/// Real detector logic lands in Step 4 (implementation).
pub fn build_findings(_obs: &Observations) -> Vec<Finding> {
    Vec::new()
}
