//! Findings layer.
//!
//! Each detector is a free function that reads `Observations` and returns
//! zero or more `Finding`s. The CLI runs them all and renders the union into
//! the report, sorted by severity.

pub mod augmented;
pub mod dnp3_engineering;
mod dns_resolver;
mod engineering_commands;
mod internet_egress;
pub mod ldap_creds;
pub mod modbus_recon;
pub mod ntlmv1;
mod ntp_external;
mod plaintext_creds;
pub mod rdp_legacy;
pub mod recon_scan;
mod smbv1;
mod stale_tls;
mod unexpected_protocols;
pub mod weak_tls_cipher;
pub mod zonewarden;

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::observe::Observations;

/// Render a host as "HOSTNAME (1.2.3.4)" when we have a hostname for
/// it (DHCP option 12 today), otherwise just the IP. The IP stays in
/// the string regardless so it's still copy-pasteable. After scrubbing,
/// this becomes `name_001 (host_001)`, which the unscrub round-trip
/// recovers verbatim.
///
/// Used by every detector when constructing evidence and summary
/// strings — so on captures that include DHCP, the report names the
/// asset the way the operator recognizes it.
pub fn host_label(ip: IpAddr, obs: &Observations) -> String {
    match obs.hostnames.get(&ip) {
        Some(name) => format!("{name} ({ip})"),
        None => ip.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    /// Short narrative for someone skimming the report. One sentence.
    pub recommendation: &'static str,
    /// Sequenced action steps tied to the actual evidence in this
    /// finding. Each step references the specific hosts / MACs / ports
    /// observed, not generic advice. See
    /// `docs/specs/investigation-playbooks.md`.
    pub playbook: Vec<String>,
}

/// Static description of a detection rule. Lives next to the detector
/// code so it can't drift. Exposed via `findings::catalog()`, the
/// `otsniff rules` subcommand, the auto-generated `docs/RULES.md`, and
/// the per-finding "Detection criteria" line in rendered reports.
///
/// A reviewer should be able to read `trigger` and predict the firing
/// behavior without reading Rust.
#[derive(Debug, Clone, Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    /// One-paragraph plain-English description of what causes the rule
    /// to fire. Names the protocol, the structural signal, and any
    /// filtering by zone or threshold.
    pub trigger: &'static str,
    /// Fields on `Observations` that the rule reads. Helps reviewers
    /// understand the input surface and the scrub stance for each
    /// rule.
    pub data_source: &'static [&'static str],
    /// External references: protocol RFCs, MITRE ICS ATT&CK techniques,
    /// CWE entries, vendor advisories.
    pub references: &'static [Reference],
}

#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub kind: ReferenceKind,
    pub label: &'static str,
    pub url: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReferenceKind {
    /// MITRE ATT&CK for ICS technique (T08xx series)
    MitreIcsAttack,
    /// IETF RFC
    Rfc,
    /// CWE category
    Cwe,
    /// CVE entry
    Cve,
    /// Protocol or industry specification (Modbus, IEC, NIST SP, etc.)
    Spec,
    /// Vendor advisory or documentation
    Vendor,
}

impl ReferenceKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MitreIcsAttack => "MITRE ATT&CK for ICS",
            Self::Rfc => "RFC",
            Self::Cwe => "CWE",
            Self::Cve => "CVE",
            Self::Spec => "Spec",
            Self::Vendor => "Vendor",
        }
    }
}

/// Every rule the tool can fire, in stable order. Source of truth for
/// `otsniff rules`, `docs/RULES.md`, and the inline trigger line in
/// rendered reports.
pub fn catalog() -> Vec<RuleMetadata> {
    vec![
        plaintext_creds::FTP_METADATA,
        plaintext_creds::TELNET_METADATA,
        plaintext_creds::HTTP_BASIC_METADATA,
        plaintext_creds::SNMP_METADATA,
        ldap_creds::LDAP_METADATA,
        ntlmv1::NTLM_METADATA,
        engineering_commands::MODBUS_METADATA,
        engineering_commands::ENIP_METADATA,
        engineering_commands::S7_METADATA,
        dnp3_engineering::METADATA,
        smbv1::METADATA,
        stale_tls::METADATA,
        weak_tls_cipher::WEAK_TLS_CIPHER_METADATA,
        rdp_legacy::RDP_LEGACY_METADATA,
        modbus_recon::MODBUS_RECON_METADATA,
        internet_egress::METADATA,
        dns_resolver::METADATA,
        ntp_external::METADATA,
        recon_scan::METADATA,
        unexpected_protocols::METADATA,
        // Zonewarden segmentation-conformance rules (ADR-0013). These fire only
        // when a `--policy` is supplied; they are not part of `run_all`.
        zonewarden::IDMZ_BYPASS_METADATA,
        zonewarden::WRONG_DIRECTION_METADATA,
        zonewarden::DENY_BY_DEFAULT_METADATA,
    ]
}

/// Look up a rule's metadata by finding id. Returns `None` if no rule
/// in the catalog has that id (typically: a detector typo). The HTML /
/// markdown renderers use this to emit the "Detection criteria" line
/// under each fired finding.
pub fn metadata_for(id: &str) -> Option<RuleMetadata> {
    catalog().into_iter().find(|m| m.id == id)
}

/// Findings for a policy-aware run (ADR-0013). Runs the zero-config rules but
/// **drops** the subnet-based `egress.ot_to_internet` — when a segmentation
/// policy is present, OT→EXTERNAL flows are owned, more precisely, by the
/// Zonewarden engine (as `zonewarden.deny_by_default` / `zonewarden.idmz_bypass`)
/// — then adds the conformance findings. Never double-reports egress.
pub fn run_with_conformance(
    obs: &Observations,
    ot_subnets: &[IpNet],
    // `::zonewarden` (the crate) — `zonewarden` alone resolves to the local
    // `findings::zonewarden` submodule below.
    conformance: &::zonewarden::types::ConformanceResult,
) -> Vec<Finding> {
    let mut out = run_all(obs, ot_subnets);
    out.retain(|f| f.id != internet_egress::METADATA.id); // dedup vs the engine
    out.extend(zonewarden::detect(conformance, obs));
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));
    out
}

pub fn run_all(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(plaintext_creds::detect(obs));
    out.extend(ldap_creds::build_findings(obs));
    out.extend(ntlmv1::build_findings(obs));
    out.extend(internet_egress::detect(obs));
    out.extend(engineering_commands::detect(obs, ot_subnets));
    out.extend(dnp3_engineering::detect(obs, ot_subnets));
    out.extend(unexpected_protocols::detect(obs, ot_subnets));
    out.extend(smbv1::detect(obs));
    out.extend(stale_tls::detect(obs));
    out.extend(weak_tls_cipher::build_findings(obs));
    out.extend(rdp_legacy::build_findings(obs));
    out.extend(modbus_recon::build_findings(obs));
    out.extend(dns_resolver::detect(obs, ot_subnets));
    out.extend(ntp_external::detect(obs, ot_subnets));
    out.extend(recon_scan::detect(obs, ot_subnets));
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));
    out
}

/// A MITRE ATT&CK for ICS technique surfaced for a finding: a display-ready
/// `label` (e.g. `"T0859 — Valid Accounts"`) and the canonical
/// `attack.mitre.org` URL. Looked up from the rule catalog by finding id —
/// the single source of truth (ADR-0014), never duplicated onto `Finding`.
#[derive(Debug, Clone, Serialize)]
pub struct MitreTechnique {
    pub label: &'static str,
    pub url: &'static str,
}

/// MITRE ATT&CK for ICS techniques for a finding id, looked up from the
/// catalog (ADR-0014). Filters `references` to `MitreIcsAttack` entries that
/// carry a url, in `references` order. Empty when the id isn't in the catalog
/// (EC-001) — the same guard the `trigger` enrichment uses.
pub fn mitre_techniques_for(id: &str) -> Vec<MitreTechnique> {
    metadata_for(id)
        .map(|m| {
            m.references
                .iter()
                .filter(|r| r.kind == ReferenceKind::MitreIcsAttack)
                .filter_map(|r| {
                    r.url.map(|url| MitreTechnique {
                        label: r.label,
                        url,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Serialize a findings slice to JSON, enriching each finding object with a
/// `mitre_techniques` array (AC-004). The MITRE data is looked up from the
/// catalog by id — not stored on `Finding` — so the runtime finding and the
/// catalog can't drift (ADR-0014). All existing finding fields are preserved.
pub fn findings_json(findings: &[Finding]) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|f| {
            let mut value = serde_json::to_value(f).expect("Finding serializes");
            if let serde_json::Value::Object(map) = &mut value {
                map.insert(
                    "mitre_techniques".to_string(),
                    serde_json::to_value(mitre_techniques_for(f.id))
                        .expect("MitreTechnique serializes"),
                );
            }
            value
        })
        .collect()
}

#[cfg(test)]
mod mitre_tests {
    use super::*;

    /// A well-formed ATT&CK-for-ICS technique URL is exactly
    /// `https://attack.mitre.org/techniques/T0<digits>/` — matching the
    /// `^https://attack\.mitre\.org/techniques/T0\d+/$` shape from AC-001.
    fn is_valid_ics_technique_url(url: &str) -> bool {
        let Some(rest) = url.strip_prefix("https://attack.mitre.org/techniques/T0") else {
            return false;
        };
        let Some(digits) = rest.strip_suffix('/') else {
            return false;
        };
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    }

    /// AC-001: every detection rule in the catalog must carry at least one MITRE
    /// ATT&CK for ICS reference, and every such reference must have a well-formed
    /// `attack.mitre.org/techniques/T0XXX/` URL. This stops a future detection
    /// rule from silently shipping without a technique mapping.
    ///
    /// Deviation from the spec's literal "every rule in `catalog()`": the three
    /// policy-gated `zonewarden.*` rules (ADR-0013) are exempt. They are IEC
    /// 62443 segmentation-*conformance* verdicts, not adversary-behavior
    /// detections — and ATT&CK for ICS models adversary techniques, while
    /// network segmentation is a *mitigation* (M0930), not a technique. The
    /// spec's AC-001 mapping table covers exactly the seven detection modules
    /// and never names the zonewarden verdicts in the MITRE context; forcing a
    /// technique onto them would be semantically wrong and require an
    /// unverifiable ID. They keep their IEC 62443 `Spec` references instead.
    #[test]
    fn every_rule_has_a_well_formed_mitre_reference() {
        for rule in catalog() {
            // Policy-gated segmentation-conformance verdicts are MITRE-exempt
            // (see doc comment): they map to IEC 62443 controls, not ATT&CK.
            if rule.id.starts_with("zonewarden.") {
                continue;
            }
            let mitre: Vec<&Reference> = rule
                .references
                .iter()
                .filter(|r| r.kind == ReferenceKind::MitreIcsAttack)
                .collect();
            assert!(
                !mitre.is_empty(),
                "rule {} has no MITRE ATT&CK for ICS reference (AC-001)",
                rule.id
            );
            for r in mitre {
                let url = r.url.unwrap_or_else(|| {
                    panic!("rule {} MITRE reference '{}' has no url", rule.id, r.label)
                });
                assert!(
                    is_valid_ics_technique_url(url),
                    "rule {} MITRE url {url} is not a well-formed \
                     attack.mitre.org/techniques/T0XXX/ URL",
                    rule.id
                );
            }
        }
    }
}
