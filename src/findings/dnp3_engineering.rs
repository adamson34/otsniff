//! ics.dnp3_engineering finding emitter — stub for S-2.04.

use ipnet::IpNet;

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "ics.dnp3_engineering",
    title: "DNP3 engineering-class commands on the wire",
    severity: Severity::High,
    trigger: "Fires when a DNP3 master issues engineering-class function codes \
              (Operate (4), Direct Operate (5), Direct Operate No Ack (6), \
              Cold Restart (13), Warm Restart (14), Initialize Data (15), \
              Initialize Application (16), Disable Unsolicited (20), \
              Enable Unsolicited (21), Save Configuration (24)) against a \
              controller. DNP3 has no native authentication in its base \
              specification; any host that can reach a DNP3 outstation on \
              tcp/20000 can send these commands.",
    data_source: &["dnp3_events (where engineering_class = true)"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0855 — Unauthorized Command Message",
            url: Some("https://attack.mitre.org/techniques/T0855/"),
        },
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0836 — Modify Parameter",
            url: Some("https://attack.mitre.org/techniques/T0836/"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "IEEE 1815-2012 — DNP3 Standard",
            url: None,
        },
    ],
};

pub fn detect(_obs: &Observations, _ot_subnets: &[IpNet]) -> Vec<Finding> {
    todo!("S-2.04: emit ics.dnp3_engineering findings from observations")
}
