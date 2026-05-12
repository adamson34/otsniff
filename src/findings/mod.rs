//! Findings layer.
//!
//! Each detector is a free function that reads `Observations` and returns
//! zero or more `Finding`s. The CLI runs them all and renders the union into
//! the report, sorted by severity.

pub mod dnp3_engineering;
mod dns_resolver;
mod engineering_commands;
mod internet_egress;
mod plaintext_creds;
mod smbv1;
mod stale_tls;
mod unexpected_protocols;

use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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
        engineering_commands::MODBUS_METADATA,
        engineering_commands::ENIP_METADATA,
        engineering_commands::S7_METADATA,
        dnp3_engineering::METADATA,
        smbv1::METADATA,
        stale_tls::METADATA,
        internet_egress::METADATA,
        dns_resolver::METADATA,
        unexpected_protocols::METADATA,
    ]
}

/// Look up a rule's metadata by finding id. Returns `None` if no rule
/// in the catalog has that id (typically: a detector typo). The HTML /
/// markdown renderers use this to emit the "Detection criteria" line
/// under each fired finding.
pub fn metadata_for(id: &str) -> Option<RuleMetadata> {
    catalog().into_iter().find(|m| m.id == id)
}

pub fn run_all(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(plaintext_creds::detect(obs));
    out.extend(internet_egress::detect(obs));
    out.extend(engineering_commands::detect(obs, ot_subnets));
    out.extend(dnp3_engineering::detect(obs, ot_subnets));
    out.extend(unexpected_protocols::detect(obs, ot_subnets));
    out.extend(smbv1::detect(obs));
    out.extend(stale_tls::detect(obs));
    out.extend(dns_resolver::detect(obs, ot_subnets));
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));
    out
}
