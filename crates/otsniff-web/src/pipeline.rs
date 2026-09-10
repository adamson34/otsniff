//! Reuses otsniff's existing synchronous analyze pipeline in-process
//! (ADR-0018 D2/D3) — the same sequence `cli.rs`'s private `analyze()`
//! helper composes: decode packets, accumulate `Observations`, build the
//! inventory + findings, render HTML/JSON. No subprocess, no async: this
//! module is plain sync code, called from an axum handler via
//! `tokio::task::spawn_blocking` so it never blocks the async runtime.

use std::path::PathBuf;

use chrono::Utc;
use ipnet::IpNet;

use otsniff::capture_source;
use otsniff::findings;
use otsniff::inventory;
use otsniff::observe::Observer;
use otsniff::pcap::iter_packets_multi;
use otsniff::report::render_html;
use otsniff::Result;

pub struct AnalyzeOutput {
    pub html: String,
    pub json: String,
    pub finding_count: usize,
    pub host_count: usize,
}

/// Default OT-zone subnets (RFC1918) — mirrors `cli.rs`'s `ot_or_default`.
pub fn default_ot_subnets() -> Vec<IpNet> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().expect("hardcoded CIDR is valid"))
        .collect()
}

pub fn run_analyze(
    inputs: &[PathBuf],
    ot_subnets: &[IpNet],
    source_label: &str,
) -> Result<AnalyzeOutput> {
    let mut observer = Observer::new(ot_subnets.to_vec());
    for pkt_result in iter_packets_multi(inputs)? {
        let pkt = pkt_result?;
        observer.observe(&pkt);
    }
    let obs = observer.finish();

    let classification = capture_source::classify(&obs);
    let asset_inventory = inventory::build(&obs);
    let rule_findings = findings::run_all(&obs, ot_subnets);
    let generated_at = Utc::now();

    let html = render_html(
        &asset_inventory,
        &rule_findings,
        &obs,
        source_label,
        generated_at,
        Some(&classification),
        None,
        None,
    )?;

    let json_payload = serde_json::json!({
        "version": otsniff::VERSION,
        "input": source_label,
        "inventory": asset_inventory,
        "findings": findings::findings_json(&rule_findings[..]),
    });
    let json = serde_json::to_string_pretty(&json_payload)?;

    Ok(AnalyzeOutput {
        html,
        json,
        finding_count: rule_findings.len(),
        host_count: asset_inventory.len(),
    })
}
