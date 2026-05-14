use ipnet::IpNet;

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "boundary.ntp_external",
    title: "OT host syncing time to public NTP",
    severity: Severity::Medium,
    trigger: "Fires when at least one flow with `dst_port = 123` (UDP) has a \
              source IP inside a configured `--ot-subnet` and a destination IP \
              that is NOT inside any configured OT subnet. OT devices should \
              sync time to an in-zone NTP server under change control; queries \
              to external NTP servers (including public pool addresses) leak \
              timing behaviour across the OT/IT boundary and introduce a \
              dependency on the external network for a safety-critical function.",
    data_source: &["flows (dst_port = 123; src in OT, dst not in OT)"],
    references: &[
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-3 SR-5.1 — Network segmentation",
            url: None,
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "Purdue Reference Model — boundary services",
            url: None,
        },
    ],
};

pub fn detect(_obs: &Observations, _ot_subnets: &[IpNet]) -> Vec<Finding> {
    todo!("S-2.09 implementer fills this in")
}
