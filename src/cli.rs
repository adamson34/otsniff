use std::io::{Read, Write};
use std::path::PathBuf;

use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;

use crate::ai::claude_cli::ClaudeCliProvider;
use crate::ai::leak_detector;
use crate::ai::prompts;
use crate::ai::AiProvider;
use crate::audit::{
    self, AiInvocationSummary, AuditLog, InputDescriptor, LeakCheckResult, LeakCheckSummary,
    ScrubSummary, UnscrubSummary,
};
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
    /// Analyze a PCAP with Claude. Internally: scrub → leak-check → invoke
    /// the local Claude Code CLI → unscrub the response → append to the
    /// markdown report. The AI never sees real IPs or MACs.
    Analyze(AnalyzeArgs),
    /// Print the detection rule catalog. Lists every finding the tool
    /// can produce, with the plain-English trigger description and
    /// references. Use this to review what the tool flags without
    /// reading Rust source.
    Rules(RulesArgs),
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
pub struct AnalyzeArgs {
    /// Path to input PCAP/PCAPNG.
    pub input: PathBuf,
    /// Output markdown report path. The rules-based report is written here,
    /// then the AI-augmented analysis is appended.
    #[arg(short = 'o', long = "output", default_value = "report.md")]
    pub output: PathBuf,
    /// Optional path to write the pseudonym map. If omitted, the map is
    /// kept in-memory only and not persisted (you can still unscrub the
    /// run's output because it's done in-process; you just can't unscrub
    /// later text against this run).
    #[arg(long = "map", value_name = "PATH")]
    pub map: Option<PathBuf>,
    /// Optional path to write the privacy audit log (JSON). Contains
    /// counts and SHA-256 hashes of the exact bytes sent to the AI
    /// provider — no real identifiers. Useful as chain-of-custody
    /// evidence for compliance review.
    #[arg(long = "audit-log", value_name = "PATH")]
    pub audit_log: Option<PathBuf>,
    /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
    #[arg(long = "ot-subnet", value_name = "CIDR")]
    pub ot_subnets: Vec<IpNet>,
    /// Optional Claude model override, passed through to `claude --model`.
    #[arg(long = "model", value_name = "MODEL")]
    pub model: Option<String>,
    /// Print parse summary + privacy ledger lines to stderr.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    /// Output format. Default: markdown.
    #[arg(long = "format", value_name = "FORMAT", default_value = "md")]
    pub format: String,
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
        Command::Analyze(a) => run_analyze(a),
        Command::Rules(a) => run_rules(a),
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
    let classification = crate::capture_source::classify(&obs);
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        &args.input.display().to_string(),
        Utc::now(),
        Some(&classification),
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
    let classification = crate::capture_source::classify(&obs);
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);

    // Two-pass scrub: render normally, then substitute every observed
    // identifier with a pseudonym. Keeps the data model unscrubbed (so
    // types stay pristine) and limits substitution to values we actually
    // saw, which avoids accidentally rewriting IP-shaped substrings in
    // unrelated text.
    let map = build_map(&obs);
    let raw_md = render_markdown(
        &inventory,
        &findings,
        &obs,
        "<scrubbed>",
        Utc::now(),
        Some(&classification),
    )?;
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

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    let ot_subnets = ot_or_default(&args.ot_subnets);
    if args.verbose {
        eprintln!(
            "otsniff {} — analyzing {}",
            crate::VERSION,
            args.input.display()
        );
    }
    let obs = analyze(&args.input, &ot_subnets, args.verbose)?;
    let classification = crate::capture_source::classify(&obs);
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);

    // 1. Build the rules-based markdown report (real values, never sent
    //    to AI).
    let raw_md = render_markdown(
        &inventory,
        &findings,
        &obs,
        "<scrubbed>",
        Utc::now(),
        Some(&classification),
    )?;

    // 2. Mint pseudonyms and produce the scrubbed payload that will go
    //    to the AI.
    let map = build_map(&obs);
    let scrubbed_md = scrub_text(&raw_md, &map);
    let scrub_summary = ScrubSummary {
        ip_pseudonyms: map.ips.len(),
        mac_pseudonyms: map.macs.len(),
        hostname_pseudonyms: map.names.len(),
    };
    if args.verbose {
        eprintln!(
            "  scrubbing... {} ip pseudonyms, {} mac pseudonyms, {} hostname pseudonyms",
            scrub_summary.ip_pseudonyms,
            scrub_summary.mac_pseudonyms,
            scrub_summary.hostname_pseudonyms,
        );
    }

    // 3. FAIL-CLOSED LEAK CHECK. This is the kill switch — if any
    //    real-looking identifier survived the scrub, abort here before
    //    invoking the provider. Two layers:
    //      a) Regex check: catches IP/MAC patterns even if the scrub
    //         layer never knew about the value (defense in depth).
    //      b) Map-value check: catches anything in the scrub map that
    //         didn't get substituted. This is what enforces the
    //         hostname privacy contract — hostnames have no clean
    //         regex shape, so the map-value check is the only signal.
    leak_detector::ensure_clean(&scrubbed_md)?;
    leak_detector::ensure_no_map_values(&scrubbed_md, &map)?;
    // We didn't actually fail closed if we reached this point. Record
    // the verdict for the audit log.
    let leak_check = LeakCheckSummary {
        regex: LeakCheckResult {
            passed: true,
            items_checked: 3, // ipv4, ipv6, mac patterns
        },
        map_value: LeakCheckResult {
            passed: true,
            items_checked: scrub_summary.total(),
        },
    };
    if args.verbose {
        eprintln!("  leak check (regex): pass — 0 ipv4/ipv6/mac-shaped patterns found",);
        eprintln!(
            "  leak check (map-value): pass — {} real values verified absent",
            leak_check.map_value.items_checked
        );
    }

    // 4. Assemble the system prompt with the capture-source qualifier and
    //    compose the user message. Both are leak-checked.
    let system_prompt = prompts::system_prompt_for(classification.ai_qualifier_tag());
    leak_detector::ensure_clean(&system_prompt)?;
    let user_message = format!("{}\n\n{}", prompts::DEFAULT_TASK, scrubbed_md);
    leak_detector::ensure_clean(&user_message)?; // belt-and-braces
    leak_detector::ensure_no_map_values(&user_message, &map)?;

    let model_label = args.model.clone().unwrap_or_else(|| "default".to_string());
    if args.verbose {
        eprintln!("  invoking claude (model: {})...", model_label);
    }
    let provider = ClaudeCliProvider::new(args.model.clone());
    let invoke_start = std::time::Instant::now();
    let scrubbed_response = provider.analyze(&system_prompt, &user_message)?;
    let elapsed = invoke_start.elapsed();
    if args.verbose {
        eprintln!(
            "    done in {:.1}s, {} bytes response",
            elapsed.as_secs_f64(),
            scrubbed_response.len(),
        );
    }

    // 5. Unscrub the AI response on this side of the boundary.
    let (unscrubbed_response, replaced, unmapped) = unscrub_text(&scrubbed_response, &map);
    if args.verbose {
        eprintln!(
            "  unscrubbing... {} pseudonyms replaced, {} unmapped",
            replaced,
            unmapped.len(),
        );
    }

    // 6. Write the combined report: rules-based markdown + AI section,
    //    using the unscrubbed (real-value) versions for the user.
    let mut combined = raw_md;
    combined.push('\n');
    combined.push_str(&unscrubbed_response);
    combined.push('\n');

    std::fs::write(&args.output, combined).map_err(|source| OtError::WriteOutput {
        path: args.output.clone(),
        source,
    })?;

    if let Some(map_path) = &args.map {
        let map_json = serde_json::to_string_pretty(&map)?;
        std::fs::write(map_path, map_json).map_err(|source| OtError::WriteOutput {
            path: map_path.clone(),
            source,
        })?;
    }

    // 7. Audit log. Only computed (and only causes the input PCAP to be
    //    re-read for hashing) when --audit-log is set. The log itself
    //    passes through both leak checks before write — even though it
    //    only carries counts + hashes, treating it as suspect on write
    //    means a future field added carelessly can't bypass the
    //    invariant.
    if let Some(audit_path) = &args.audit_log {
        let (size_bytes, sha256) = audit::sha256_file_hex(&args.input)?;
        let log = AuditLog {
            schema_version: audit::SCHEMA_VERSION,
            otsniff_version: crate::VERSION.to_string(),
            timestamp: Utc::now(),
            input_pcap: InputDescriptor {
                path: args.input.display().to_string(),
                size_bytes,
                sha256,
            },
            scrub: scrub_summary,
            leak_check,
            ai_provider: AiInvocationSummary {
                command: format!(
                    "claude -p{}",
                    args.model
                        .as_deref()
                        .map(|m| format!(" --model {m}"))
                        .unwrap_or_default()
                ),
                model: model_label,
                system_prompt_bytes: system_prompt.len(),
                system_prompt_sha256: audit::sha256_hex(&system_prompt),
                user_message_bytes: user_message.len(),
                user_message_sha256: audit::sha256_hex(&user_message),
                response_bytes: scrubbed_response.len(),
                response_sha256: audit::sha256_hex(&scrubbed_response),
                elapsed_seconds: elapsed.as_secs_f64(),
            },
            unscrub: UnscrubSummary {
                pseudonyms_replaced: replaced,
                pseudonyms_unmapped: unmapped.len(),
            },
        };
        let log_json = serde_json::to_string_pretty(&log)?;
        // Belt-and-braces: scan the rendered audit log itself for any
        // real identifier before write. With the current fields this
        // is impossible — but a future contributor might add a field
        // without thinking about the invariant. Better to fail-closed
        // than ship a leaky log.
        leak_detector::ensure_clean(&log_json)?;
        leak_detector::ensure_no_map_values(&log_json, &map)?;
        std::fs::write(audit_path, log_json).map_err(|source| OtError::WriteOutput {
            path: audit_path.clone(),
            source,
        })?;
        if args.verbose {
            eprintln!("  wrote audit log → {}", audit_path.display());
        }
    }

    eprintln!(
        "wrote {} ({} pseudonyms unscrubbed{}{}{})",
        args.output.display(),
        replaced,
        if unmapped.is_empty() {
            String::new()
        } else {
            format!(", {} unknown left as-is", unmapped.len())
        },
        match &args.map {
            Some(p) => format!(", map saved to {}", p.display()),
            None => String::new(),
        },
        match &args.audit_log {
            Some(p) => format!(", audit log → {}", p.display()),
            None => String::new(),
        }
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

fn run_rules(args: RulesArgs) -> Result<()> {
    let format = match args.format.as_str() {
        "md" | "markdown" => crate::rule_catalog::CatalogFormat::Markdown,
        "json" => crate::rule_catalog::CatalogFormat::Json,
        other => {
            return Err(OtError::Parse(format!(
                "unknown rules format '{other}'; expected 'md' or 'json'"
            )))
        }
    };
    let catalog = crate::findings::catalog();
    let rendered = crate::rule_catalog::render(&catalog, format);
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .map_err(|source| OtError::WriteOutput {
            path: "<stdout>".into(),
            source,
        })?;
    Ok(())
}
