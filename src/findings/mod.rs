//! Findings layer.
//!
//! Each detector is a free function that reads `Observations` and returns
//! zero or more `Finding`s. The CLI runs them all and renders the union into
//! the report, sorted by severity.

mod engineering_commands;
mod internet_egress;
mod plaintext_creds;
mod unexpected_protocols;

use ipnet::IpNet;
use serde::Serialize;

use crate::observe::Observations;

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

pub fn run_all(obs: &Observations, ot_subnets: &[IpNet]) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(plaintext_creds::detect(obs));
    out.extend(internet_egress::detect(obs));
    out.extend(engineering_commands::detect(obs, ot_subnets));
    out.extend(unexpected_protocols::detect(obs, ot_subnets));
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));
    out
}
