use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::observe::{NtlmVersion, Observations};

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const NTLM_METADATA: RuleMetadata = RuleMetadata {
    id: "compat.ntlmv1",
    title: "NTLMv1 authentication observed",
    severity: Severity::High,
    trigger: "Fires when at least one NTLMSSP NEGOTIATE_MESSAGE is observed \
              in a TCP payload (ports 445, 139, 80, 443, 8080, 135) with \
              NTLMSSP_NEGOTIATE_NTLM (bit 9, 0x00000200) set and \
              NTLMSSP_NEGOTIATE_NTLM2_KEY (bit 19, 0x00080000) unset. \
              NTLMv1 challenges are trivially crackable with off-the-shelf \
              tools (e.g. hashcat, Responder) and should not appear on OT \
              networks. NTLMv2 events are excluded — a separate rule covers \
              those.",
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

/// AC-002 (BC-3.04.004): emit one `compat.ntlmv1` finding per unique (src, dst)
/// pair that has at least one `NtlmVersion::V1` event.
///
/// NTLMv2 events are skipped (EC-001 — different rule). Evidence is capped at
/// 5 samples per finding to keep reports readable.
pub fn build_findings(obs: &Observations) -> Vec<Finding> {
    // Accumulate V1 events by (src, dst) pair.
    // BTreeMap gives deterministic iteration order for stable snapshots.
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<&crate::observe::NtlmEvent>> = BTreeMap::new();

    for event in &obs.ntlm_events {
        if event.version != NtlmVersion::V1 {
            continue; // EC-001: skip V2
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
            "{} NTLMv1 NEGOTIATE message(s) from {} to {}. NTLMv1 hashes are \
             trivially crackable (Responder / hashcat); any captured exchange \
             exposes Active Directory credentials.",
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
                    "{} -> {}:{} — NTLMv1 NEGOTIATE",
                    host_label(ev.src, obs),
                    host_label(ev.dst, obs),
                    ev.dst_port,
                )
            })
            .collect();

        let playbook = vec![
            format!(
                "Identify the source host: {}. Walk its MAC to a switch port using the \
                 asset inventory.",
                host_label(*src, obs)
            ),
            "Enforce NTLMv2 and reject NTLMv1 via Group Policy: Computer Configuration → \
             Windows Settings → Security Settings → Local Policies → Security Options → \
             'Network Security: LAN Manager authentication level' → \
             'Send NTLMv2 response only. Refuse LM & NTLM'."
                .to_string(),
            "If the source is an OT-class device (HMI, EWS) that cannot be updated to \
             NTLMv2, isolate it on a dedicated management VLAN and ensure no Responder \
             or similar tool can intercept its challenges on the wire."
                .to_string(),
            "Consider rotating any passwords used by this host — NTLMv1 challenges \
             seen on the wire may already have been captured by a passive attacker."
                .to_string(),
        ];

        findings.push(Finding {
            id: "compat.ntlmv1",
            severity: Severity::High,
            title: format!(
                "NTLMv1 authentication from {} to {}",
                host_label(*src, obs),
                host_label(*dst, obs),
            ),
            summary,
            evidence,
            recommendation: "Enforce NTLMv2-only policy via Group Policy and retire NTLMv1. \
                             NTLMv1 hashes are crackable in seconds with commodity hardware.",
            playbook,
        });
    }

    findings
}
