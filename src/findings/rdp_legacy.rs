//! S-2.08: `creds.rdp_no_nla` — RDP connections negotiated without NLA.
//!
//! Fires at severity Critical when an X.224 Connection Confirm PDU on tcp/3389
//! advertises `selectedProtocol & 0x01 == 0` (PROTOCOL_RDP — no SSL/TLS,
//! no CredSSP/HYBRID, no HYBRID_EX). These connections carry RDP data
//! without any transport-layer encryption or pre-authentication, making
//! credential capture and session hijacking trivial for a passive observer
//! on the same VLAN.
//!
//! See S-2.08 AC-002 (BC-3.04.006) for the full acceptance criteria and
//! edge-case table.

use crate::observe::Observations;

use super::{Finding, Reference, ReferenceKind, RuleMetadata, Severity};

/// Rule metadata for `creds.rdp_no_nla`.
///
/// GREEN-BY-DESIGN: pure `const` value initializer; zero branching, no I/O,
/// no non-trivial helper calls, ≤ 3 effective lines of payload.
pub const RDP_LEGACY_METADATA: RuleMetadata = RuleMetadata {
    id: "creds.rdp_no_nla",
    title: "RDP connection without Network Level Authentication (NLA)",
    severity: Severity::Critical,
    trigger: "Fires when an X.224 Connection Confirm PDU on tcp/3389 contains an \
              RDP_NEG_RSP block whose selectedProtocol field has bit 0 clear \
              (PROTOCOL_RDP = 0x00000000). This means the server accepted a \
              connection with no SSL/TLS wrapping and no CredSSP pre-authentication \
              (NLA). Without NLA the Windows logon screen is rendered before \
              authentication, enabling credential-harvesting attacks and exposing \
              the session to passive capture on the local network segment.",
    data_source: &["rdp_events"],
    references: &[
        Reference {
            kind: ReferenceKind::MitreIcsAttack,
            label: "T0822 — External Remote Services",
            url: Some(
                "https://attack.mitre.org/techniques/T0822/",
            ),
        },
        Reference {
            kind: ReferenceKind::Cwe,
            label: "CWE-308 — Use of Single-factor Authentication",
            url: Some("https://cwe.mitre.org/data/definitions/308.html"),
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "MS-RDPBCGR §2.2.1.2 — RDP Negotiation Response (RDP_NEG_RSP)",
            url: Some(
                "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817",
            ),
        },
    ],
};

/// Detect RDP connections negotiated without NLA (S-2.08, BC-3.04.006).
///
/// Returns one `Finding` per distinct `(src, dst)` pair that completed an RDP
/// Connection Confirm without NLA (`selected_protocol & 0x01 == 0`). Rolls up
/// multiple observed connections between the same host pair into a single
/// finding with an evidence count.
///
/// GREEN-BY-DESIGN: the stub body returns `Vec::new()` because wiring this
/// function into `findings::mod::run_all` (exercised by all snapshot tests)
/// before the implementation exists would cascade snapshot regressions. The
/// implementer promotes this to real logic in Step 6.
/// Self-check (BC-5.38.005 invariant 1): "If I include this real
/// implementation, will the test for this function pass trivially without any
/// implementer work?" — No: `rdp_events` is always empty at stub stage, so a
/// real body would also return `Vec::new()`. A `Vec::new()` return here is
/// therefore GREEN-BY-DESIGN for the stub phase: it is correct-by-construction
/// given the empty input vector, has zero branching, no I/O, no non-trivial
/// helpers, and ≤ 1 line of body. The implementer will replace it with a
/// `BTreeMap`-grouped loop in Step 6.
pub fn build_findings(_obs: &Observations) -> Vec<Finding> {
    Vec::new()
}
