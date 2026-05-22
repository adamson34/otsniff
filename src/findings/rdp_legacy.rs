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

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

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
/// Detect RDP connections negotiated without NLA (S-2.08, BC-3.04.006).
///
/// Returns one `Finding` per distinct `(src, dst)` pair that completed an RDP
/// Connection Confirm without NLA (`selected_protocol == 0x00000000`, exact
/// equality). PROTOCOL_SSL (0x01), PROTOCOL_HYBRID (0x02), and PROTOCOL_HYBRID_EX
/// (0x08) are all secure and must not fire — the story's AC-002 bit-test
/// `& 0x01 == 0` is incorrect and is intentionally not used here.
/// Rolls up multiple observed connections between the same host pair into a
/// single finding with an evidence count.
pub fn build_findings(obs: &Observations) -> Vec<Finding> {
    // Accumulate no-NLA events by (src, dst) pair.
    // BTreeMap gives deterministic iteration order for stable snapshots.
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<&crate::observe::RdpEvent>> = BTreeMap::new();

    for event in &obs.rdp_events {
        // BC-3.04.006: fire only on exact PROTOCOL_RDP (0x00000000).
        // PROTOCOL_SSL (0x01), PROTOCOL_HYBRID (0x02), PROTOCOL_HYBRID_EX (0x08)
        // are all acceptable and must not fire.
        if event.selected_protocol != 0x00000000 {
            continue;
        }
        by_pair
            .entry((event.src, event.dst))
            .or_default()
            .push(event);
    }

    if by_pair.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for ((src, dst), events) in &by_pair {
        let count = events.len();
        let summary = format!(
            "{} RDP connection(s) from {} to {} negotiated without Network Level \
             Authentication (NLA). The RDP_NEG_RSP selectedProtocol field is \
             PROTOCOL_RDP (0x00000000), meaning no SSL/TLS wrapping and no \
             CredSSP pre-authentication was applied. Without NLA the Windows \
             logon screen is rendered before authentication, enabling \
             credential-harvesting attacks and exposing the session to passive \
             capture on the local network segment.",
            count,
            host_label(*src, obs),
            host_label(*dst, obs),
        );

        // Collect evidence lines, one per event, capped at 5.
        let evidence: Vec<String> = events
            .iter()
            .take(5)
            .map(|ev| {
                format!(
                    "{} -> {}:{} — RDP without NLA (selectedProtocol=0x{:08X})",
                    host_label(ev.src, obs),
                    host_label(ev.dst, obs),
                    ev.dst_port,
                    ev.selected_protocol,
                )
            })
            .collect();

        let playbook = vec![
            format!(
                "Identify the RDP server: {}. Verify whether NLA is enforced in the \
                 server's System Properties → Remote settings → 'Allow connections only \
                 from computers running Remote Desktop with Network Level Authentication'.",
                host_label(*dst, obs)
            ),
            format!(
                "Identify the initiating client: {}. Check whether the client has been \
                 configured to bypass NLA (e.g. RDP file with 'enablecredsspsupport:i:0').",
                host_label(*src, obs)
            ),
            "Enable NLA on all RDP servers. On Windows: Group Policy → Computer \
             Configuration → Administrative Templates → Windows Components → \
             Remote Desktop Services → Remote Desktop Session Host → Security → \
             'Require use of specific security layer' → 'SSL (TLS 1.0)' is \
             insufficient; also set 'Require NLA' to Enabled."
                .to_string(),
            "If legacy clients cannot support NLA, isolate the RDP server behind a \
             VPN or jump host that enforces NLA, or deploy an RD Gateway that \
             terminates TLS before the inner RDP connection."
                .to_string(),
            "Consider rotating credentials for any accounts that logged in via \
             non-NLA RDP — the logon screen may have been visible to a passive \
             observer on the same VLAN segment."
                .to_string(),
        ];

        findings.push(Finding {
            id: "creds.rdp_no_nla",
            severity: Severity::Critical,
            title: format!(
                "RDP connection without NLA from {} to {}",
                host_label(*src, obs),
                host_label(*dst, obs),
            ),
            summary,
            evidence,
            recommendation: "Enable Network Level Authentication (NLA) on all RDP servers. \
                             Without NLA the Windows logon screen is rendered before \
                             authentication, enabling credential-harvesting attacks.",
            playbook,
        });
    }

    findings
}
