use std::path::PathBuf;

use chrono::Utc;
use clap::Parser;
use ipnet::IpNet;

use crate::error::{OtError, Result};
use crate::observe::Observer;
use crate::pcap::iter_packets;
use crate::report::render_html;

/// One-shot OT-aware PCAP triage.
///
/// Reads a span-port capture and produces a self-contained HTML report
/// (asset inventory + ranked findings) suitable for handing to a plant
/// manager or IT director.
#[derive(Parser, Debug)]
#[command(name = "otsniff", version, about, long_about = None)]
pub struct Args {
    /// Path to input PCAP/PCAPNG file.
    pub input: PathBuf,

    /// Output HTML report path.
    #[arg(short = 'o', long = "output", default_value = "report.html")]
    pub output: PathBuf,

    /// CIDR ranges to treat as OT zones (repeatable).
    /// Findings like "internet egress from OT" use these to decide what counts as OT.
    /// Default: RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    #[arg(long = "ot-subnet", value_name = "CIDR")]
    pub ot_subnets: Vec<IpNet>,

    /// Also write findings + inventory as JSON to this path.
    #[arg(long = "json", value_name = "PATH")]
    pub json: Option<PathBuf>,

    /// Print a one-line summary to stderr while parsing.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

pub fn run() -> Result<()> {
    let args = Args::parse();
    let ot_subnets = if args.ot_subnets.is_empty() {
        default_ot_subnets()
    } else {
        args.ot_subnets.clone()
    };

    if args.verbose {
        eprintln!(
            "otsniff {} — reading {}",
            crate::VERSION,
            args.input.display()
        );
    }

    let mut observer = Observer::new(ot_subnets.clone());
    let mut packet_count: u64 = 0;
    for pkt in iter_packets(&args.input)? {
        observer.observe(&pkt?);
        packet_count += 1;
    }
    let observations = observer.finish();

    if args.verbose {
        eprintln!(
            "  parsed {} packets, {} hosts, {} flows",
            packet_count,
            observations.hosts.len(),
            observations.flows.len()
        );
    }

    let inventory = crate::inventory::build(&observations);
    let findings = crate::findings::run_all(&observations, &ot_subnets);

    let html = render_html(
        &inventory,
        &findings,
        &observations,
        &args.input.display().to_string(),
        Utc::now(),
    )?;
    std::fs::write(&args.output, html).map_err(|source| OtError::WriteOutput {
        path: args.output.clone(),
        source,
    })?;

    if let Some(json_path) = &args.json {
        let payload = serde_json::json!({
            "version": crate::VERSION,
            "input": args.input.display().to_string(),
            "inventory": inventory,
            "findings": findings,
        });
        std::fs::write(json_path, serde_json::to_string_pretty(&payload)?).map_err(|source| {
            OtError::WriteOutput {
                path: json_path.clone(),
                source,
            }
        })?;
    }

    eprintln!(
        "wrote {} ({} findings across {} hosts)",
        args.output.display(),
        findings.len(),
        inventory.len()
    );
    Ok(())
}

fn default_ot_subnets() -> Vec<IpNet> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().expect("hardcoded CIDR is valid"))
        .collect()
}
