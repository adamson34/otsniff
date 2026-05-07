use std::io::{Read, Write};
use std::path::PathBuf;

use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;

use crate::error::{OtError, Result};
use crate::observe::Observer;
use crate::pcap::iter_packets;
use crate::report::render_html;
use crate::report_md::render_markdown;
use crate::scrub::{build_map, scrub_text, unscrub_text, ScrubMap};

/// One-shot OT-aware PCAP triage.
///
/// Three modes: `report` produces an HTML report (the v0.1 behavior),
/// `scrub` produces an AI-safe markdown report plus a pseudonym map,
/// `unscrub` reverses pseudonyms in any text using a saved map.
#[derive(Parser, Debug)]
#[command(name = "otsniff", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Render an HTML report from a PCAP/PCAPNG.
    Report(ReportArgs),
    /// Render a markdown report with all sensitive identifiers replaced by
    /// stable pseudonyms. Also writes a map file you can later unscrub with.
    Scrub(ScrubArgs),
    /// Replace pseudonyms in a text file (e.g. an LLM's response) with their
    /// real values, using a previously saved map.
    Unscrub(UnscrubArgs),
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Path to input PCAP/PCAPNG.
    pub input: PathBuf,
    /// Output HTML report path.
    #[arg(short = 'o', long = "output", default_value = "report.html")]
    pub output: PathBuf,
    /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
    #[arg(long = "ot-subnet", value_name = "CIDR")]
    pub ot_subnets: Vec<IpNet>,
    /// Also write findings + inventory as JSON to this path.
    #[arg(long = "json", value_name = "PATH")]
    pub json: Option<PathBuf>,
    /// Print parse summary to stderr.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct ScrubArgs {
    /// Path to input PCAP/PCAPNG.
    pub input: PathBuf,
    /// Output markdown report (AI-safe).
    #[arg(short = 'o', long = "output", default_value = "report.md")]
    pub output: PathBuf,
    /// Path to write the pseudonym map (JSON). Required — without it you
    /// can't unscrub later.
    #[arg(long = "map", value_name = "PATH")]
    pub map: PathBuf,
    /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
    #[arg(long = "ot-subnet", value_name = "CIDR")]
    pub ot_subnets: Vec<IpNet>,
    /// Print parse summary to stderr.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct UnscrubArgs {
    /// Path to the map produced by `scrub`.
    #[arg(long = "map", value_name = "PATH")]
    pub map: PathBuf,
    /// Input text file. If omitted, reads from stdin.
    pub input: Option<PathBuf>,
    /// Output path. If omitted, writes to stdout.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
    /// Fail if the input contains pseudonyms not present in the map. Off by
    /// default — unknown tokens are left as-is so the AI can mention things
    /// outside what we observed (port numbers, function codes, etc.).
    #[arg(long = "strict")]
    pub strict: bool,
}

pub fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Report(a) => run_report(a),
        Command::Scrub(a) => run_scrub(a),
        Command::Unscrub(a) => run_unscrub(a),
    }
}

fn ot_or_default(supplied: &[IpNet]) -> Vec<IpNet> {
    if supplied.is_empty() {
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            .iter()
            .map(|s| s.parse().expect("hardcoded CIDR is valid"))
            .collect()
    } else {
        supplied.to_vec()
    }
}

fn analyze(
    input: &std::path::Path,
    ot_subnets: &[IpNet],
    verbose: bool,
) -> Result<crate::observe::Observations> {
    let mut observer = Observer::new(ot_subnets.to_vec());
    let mut packet_count: u64 = 0;
    for pkt in iter_packets(input)? {
        observer.observe(&pkt?);
        packet_count += 1;
    }
    let obs = observer.finish();
    if verbose {
        eprintln!(
            "  parsed {} packets, {} hosts, {} flows",
            packet_count,
            obs.hosts.len(),
            obs.flows.len()
        );
    }
    Ok(obs)
}

fn run_report(args: ReportArgs) -> Result<()> {
    let ot_subnets = ot_or_default(&args.ot_subnets);
    if args.verbose {
        eprintln!(
            "otsniff {} — reading {}",
            crate::VERSION,
            args.input.display()
        );
    }
    let obs = analyze(&args.input, &ot_subnets, args.verbose)?;
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);
    let html = render_html(
        &inventory,
        &findings,
        &obs,
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

fn run_scrub(args: ScrubArgs) -> Result<()> {
    let ot_subnets = ot_or_default(&args.ot_subnets);
    if args.verbose {
        eprintln!(
            "otsniff {} — scrubbing {}",
            crate::VERSION,
            args.input.display()
        );
    }
    let obs = analyze(&args.input, &ot_subnets, args.verbose)?;
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);

    // Two-pass scrub: render normally, then substitute every observed
    // identifier with a pseudonym. Keeps the data model unscrubbed (so
    // types stay pristine) and limits substitution to values we actually
    // saw, which avoids accidentally rewriting IP-shaped substrings in
    // unrelated text.
    let map = build_map(&obs);
    let raw_md = render_markdown(&inventory, &findings, &obs, "<scrubbed>", Utc::now())?;
    let md = scrub_text(&raw_md, &map);

    std::fs::write(&args.output, md).map_err(|source| OtError::WriteOutput {
        path: args.output.clone(),
        source,
    })?;
    let map_json = serde_json::to_string_pretty(&map)?;
    std::fs::write(&args.map, map_json).map_err(|source| OtError::WriteOutput {
        path: args.map.clone(),
        source,
    })?;

    eprintln!(
        "wrote {} (scrubbed) and {} (map). Paste {} into your AI of choice; \
         feed the response back through `otsniff unscrub --map {}`.",
        args.output.display(),
        args.map.display(),
        args.output.display(),
        args.map.display()
    );
    Ok(())
}

fn run_unscrub(args: UnscrubArgs) -> Result<()> {
    let map_bytes = std::fs::read(&args.map).map_err(|source| OtError::InputOpen {
        path: args.map.clone(),
        source,
    })?;
    let map: ScrubMap = serde_json::from_slice(&map_bytes)?;

    let input_text = match &args.input {
        Some(p) => std::fs::read_to_string(p).map_err(|source| OtError::InputOpen {
            path: p.clone(),
            source,
        })?,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|source| OtError::InputOpen {
                    path: "<stdin>".into(),
                    source,
                })?;
            buf
        }
    };

    let (output, replaced, unmapped) = unscrub_text(&input_text, &map);

    if args.strict && !unmapped.is_empty() {
        return Err(OtError::Parse(format!(
            "found {} pseudonym(s) with no entry in map (strict mode): {}",
            unmapped.len(),
            unmapped
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    match &args.output {
        Some(p) => {
            std::fs::write(p, output).map_err(|source| OtError::WriteOutput {
                path: p.clone(),
                source,
            })?;
            eprintln!(
                "wrote {} ({} pseudonyms replaced{})",
                p.display(),
                replaced,
                if unmapped.is_empty() {
                    String::new()
                } else {
                    format!(", {} unknown left as-is", unmapped.len())
                }
            );
        }
        None => {
            std::io::stdout()
                .write_all(output.as_bytes())
                .map_err(|source| OtError::WriteOutput {
                    path: "<stdout>".into(),
                    source,
                })?;
        }
    }
    Ok(())
}
