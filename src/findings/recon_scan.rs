//! recon.port_scan detector — fires when a single source talks to
//! many distinct destinations on the same port within the capture.
//! Stub for S-2.10. detect() is `todo!()` until the implementer
//! lands the real logic.

use ipnet::IpNet;

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "recon.port_scan",
    title: "Port scan — single source to many destinations on the same port",
    severity: Severity::Medium,
    trigger: "Fires when a single source IP talks to >= 5 distinct destination \
              IPs on the same destination port + protocol within the capture \
              window (PORT_SCAN_THRESHOLD = 5). Severity escalates to High at \
              >= 25 distinct destinations. Broadcast and multicast destination \
              addresses are excluded from the count.",
    data_source: &["flows (grouped by src_ip, dst_port, proto; counting distinct dst_ip)"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0846 — Remote System Discovery",
            url: Some("https://attack.mitre.org/techniques/T0846/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-3 SR-7.7 — Least privilege",
            url: None,
        },
    ],
};

pub fn detect(_obs: &Observations, _ot_subnets: &[IpNet]) -> Vec<Finding> {
    todo!("S-2.10: implement recon.port_scan detector")
}
