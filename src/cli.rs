use std::io::{Read, Write};
use std::path::PathBuf;

use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

use crate::ai::claude_cli::ClaudeCliProvider;
use crate::ai::leak_detector;
use crate::ai::prompts;
use crate::ai::AiProvider;
use crate::audit::{
    self, AiInvocationSummary, AuditLog, InputDescriptor, LeakCheckResult, LeakCheckSummary,
    ScrubSummary, UnscrubSummary,
};
use crate::capture_source::DeclaredSource;
use crate::error::{OtError, Result};

/// Source-label sentinel used in the markdown payload sent to the AI
/// provider.
///
/// **F-ADV-P5-001:** the PCAP basename is operator BCSI (NERC CIP-011
/// protected info) — names like `acme-plant-alpha-line3-2026-05-22.pcap`
/// embed plant / line / facility identifiers that the scrub layer
/// cannot pseudonymize because they sit outside the parsed PCAP bytes.
/// The leak detector's regex matches IP/MAC shape only, and the
/// map-value check only knows DHCP-derived hostnames. So we substitute
/// a constant sentinel before the scrub-and-send step. The HTML report
/// and local sidecar still display the real basename — the sentinel
/// applies only to bytes destined for the external AI provider.
///
/// Mirrors the existing pattern in `run_scrub` (cli.rs:525) where the
/// markdown bound for the user's external AI also uses `"<scrubbed>"`.
pub const AI_INPUT_LABEL: &str = "<scrubbed>";

/// CLI form of `DeclaredSource`. Separate enum so we own the clap
/// `ValueEnum` derive without polluting the core type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum SourceTypeArg {
    Span,
    HostSide,
    Tap,
}

impl From<SourceTypeArg> for DeclaredSource {
    fn from(a: SourceTypeArg) -> Self {
        match a {
            SourceTypeArg::Span => DeclaredSource::Span,
            SourceTypeArg::HostSide => DeclaredSource::HostSide,
            SourceTypeArg::Tap => DeclaredSource::Tap,
        }
    }
}
use crate::observe::Observer;
use crate::pcap::iter_packets;
use crate::progress::ProgressReporter;
use crate::report::render_html;
use crate::report_md::render_markdown;
use crate::scrub::{build_map, merge_map, scrub_text, unscrub_text, ScrubMap};

/// One-shot OT-aware PCAP triage.
///
/// Primary command: `analyze` reads a PCAP and writes an HTML report.
/// Pass `--ai` to also append a Claude-generated section (privacy-
/// preserving — the AI never sees real IPs/MACs/hostnames, and a
/// chain-of-custody audit log is written alongside).
///
/// Advanced commands: `scrub` / `unscrub` give a two-step manual
/// workflow for users who want to drive their own AI (Claude.ai web
/// UI, ChatGPT, local Ollama). `rules` prints the detection catalog.
#[derive(Parser, Debug)]
#[command(name = "otsniff", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Read a PCAP and write an HTML report. With `--ai`, also append a
    /// Claude-generated analysis section (scrub → leak-check → invoke
    /// the local Claude Code CLI → unscrub → embed). The AI never sees
    /// real IPs, MACs, or hostnames; a chain-of-custody audit log is
    /// written automatically when `--ai` is on.
    Analyze(AnalyzeArgs),
    /// Render a markdown report with all sensitive identifiers replaced
    /// by stable pseudonyms. Also writes a map file you can later
    /// unscrub with. Advanced: use this if you want to paste into a
    /// different AI (Claude.ai web, ChatGPT, local Ollama). Most users
    /// should use `analyze --ai` instead.
    Scrub(ScrubArgs),
    /// Replace pseudonyms in a text file (e.g. an LLM's response) with
    /// their real values, using a previously saved map. Advanced —
    /// counterpart to `scrub`.
    Unscrub(UnscrubArgs),
    /// Print the detection rule catalog. Lists every finding the tool
    /// can produce, with the plain-English trigger description and
    /// references. Use this to review what the tool flags without
    /// reading Rust source.
    Rules(RulesArgs),
    /// Compare two captures and emit a delta report: new and gone hosts,
    /// finding deltas, role inference shifts, and flow-volume shifts.
    /// Identification is by pseudonym from the merged scrub maps, so the
    /// comparison is stable across captures of the same network.
    //
    // Internal traceability: BC-9.05.001 (subcommand surface),
    // BC-3.08.001..003 (delta shape). See docs/ROADMAP.md P1-3.
    Diff {
        /// Baseline capture (the "before" PCAP).
        baseline_pcap: PathBuf,
        /// Current capture (the "after" PCAP).
        current_pcap: PathBuf,
        /// Merged scrub map for the baseline capture.
        #[arg(long)]
        baseline_map: PathBuf,
        /// Merged scrub map for the current capture.
        #[arg(long)]
        current_map: PathBuf,
        /// Output report path (.html, .md, or .json).
        #[arg(short, long)]
        output: PathBuf,
        /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
        /// MUST match the value passed to `analyze` for the same captures, or
        /// the findings layer will classify hosts differently and produce
        /// spurious findings_new/findings_resolved entries (F-ADV-P1-001).
        #[arg(long = "ot-subnet", value_name = "CIDR")]
        ot_subnets: Vec<IpNet>,
        /// Ratio threshold for flow-volume shift detection (default 2.0).
        /// A flow appearing in both captures is reported as a shift when
        /// the larger byte count is at least this multiple of the smaller.
        /// Values < 1.0 are rejected at parse time.
        #[arg(long, default_value_t = crate::diff::DEFAULT_FLOW_SHIFT_MULTIPLIER)]
        flow_shift_multiplier: f64,
    },
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
    /// Declare the capture provenance: `span`, `host-side`, or `tap`.
    /// See `--source-type` on `analyze`.
    #[arg(long = "source-type", value_name = "TYPE", value_enum)]
    pub source_type: Option<SourceTypeArg>,
    /// Optional path to a previously saved pseudonym map to use as a
    /// baseline. When provided, real identifiers already in the baseline
    /// map reuse their existing pseudonyms; new identifiers are appended
    /// with fresh pseudonyms. If omitted, the current behavior is
    /// preserved (a brand-new map is built from this capture alone).
    ///
    /// See S-6.01 / BC-5.03.001 for the stability contract.
    #[arg(long = "baseline-map", value_name = "PATH")]
    pub baseline_map: Option<PathBuf>,
    /// Print parse summary to stderr.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to input PCAP/PCAPNG.
    pub input: PathBuf,
    /// Output HTML report path.
    #[arg(short = 'o', long = "output", default_value = "report.html")]
    pub output: PathBuf,
    /// Also run the AI analysis pass. Internally: scrub → fail-closed
    /// leak check → invoke the local Claude Code CLI → unscrub →
    /// embed as a section in the rendered HTML. The AI never sees
    /// real IPs, MACs, or hostnames. When this is set, the privacy
    /// audit log is written automatically alongside the report (see
    /// `--audit-log`).
    #[arg(long = "ai")]
    pub ai: bool,
    /// Override the privacy audit log path. Only meaningful when
    /// `--ai` is set; default is to derive a `.audit.json` file
    /// alongside the report output. The log carries counts and
    /// SHA-256 hashes — no real identifiers — and serves as
    /// chain-of-custody evidence for compliance review.
    #[arg(long = "audit-log", value_name = "PATH")]
    pub audit_log: Option<PathBuf>,
    /// Also write the markdown form of the report to this path.
    /// Useful if you want the source the AI saw (pre-render).
    #[arg(long = "md", value_name = "PATH")]
    pub md: Option<PathBuf>,
    /// Also write the findings + inventory as JSON to this path.
    #[arg(long = "json", value_name = "PATH")]
    pub json: Option<PathBuf>,
    /// Optional path to write the pseudonym map. Only meaningful when
    /// `--ai` is set. Lets you unscrub follow-up AI text later
    /// against the same run. Most users don't need this — the AI
    /// section in the HTML is already unscrubbed inline.
    #[arg(long = "map", value_name = "PATH")]
    pub map: Option<PathBuf>,
    /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
    #[arg(long = "ot-subnet", value_name = "CIDR")]
    pub ot_subnets: Vec<IpNet>,
    /// Declare the capture provenance: `span`, `host-side`, or `tap`.
    /// When set, this overrides the heuristic in the report; the
    /// heuristic still runs as a guard and warns on stderr if it
    /// disagrees.
    #[arg(long = "source-type", value_name = "TYPE", value_enum)]
    pub source_type: Option<SourceTypeArg>,
    /// Optional Claude model override, passed through to `claude --model`.
    /// Only meaningful when `--ai` is set.
    #[arg(long = "model", value_name = "MODEL")]
    pub model: Option<String>,
    /// Print the scrubbed prompt to stderr and pause for confirmation
    /// before invoking claude. Defense-in-depth — the automated leak
    /// detector still runs; this adds a human eyeball.
    #[arg(long = "review-scrub")]
    pub review_scrub: bool,
    /// Print parse summary + (with `--ai`) privacy ledger lines to stderr.
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
        Command::Analyze(a) => run_analyze(a),
        Command::Scrub(a) => run_scrub(a),
        Command::Unscrub(a) => run_unscrub(a),
        Command::Rules(a) => run_rules(a),
        Command::Diff {
            baseline_pcap,
            current_pcap,
            baseline_map,
            current_map,
            output,
            ot_subnets,
            flow_shift_multiplier,
        } => run_diff(
            baseline_pcap,
            current_pcap,
            baseline_map,
            current_map,
            output,
            ot_subnets,
            flow_shift_multiplier,
        ),
    }
}

/// Run the `diff` subcommand (AC-001 / BC-9.05.001).
///
/// Loads both PCAPs and their scrub maps, builds observations + findings for
/// each side, calls `crate::diff::compute`, and writes the result. For `.json`
/// outputs the `Diff` is serialized as pretty JSON. For `.html` and `.md`
/// outputs a placeholder is written — full rendering arrives in S-6.03.
fn run_diff(
    baseline_pcap: PathBuf,
    current_pcap: PathBuf,
    baseline_map_path: PathBuf,
    current_map_path: PathBuf,
    output: PathBuf,
    user_ot_subnets: Vec<IpNet>,
    flow_shift_multiplier: f64,
) -> Result<()> {
    // F-ADV-P1-002: validate the user-supplied multiplier at parse time so a
    // bogus value (e.g. 0 or negative) fails early instead of silently
    // producing zero shifts.
    if !flow_shift_multiplier.is_finite() || flow_shift_multiplier < 1.0 {
        return Err(OtError::Parse(format!(
            "--flow-shift-multiplier must be a finite value ≥ 1.0; got {flow_shift_multiplier}"
        )));
    }

    // F-ADV-P1-001: use the user-supplied OT subnets (or RFC1918 defaults).
    // Without this, the findings layer always treated non-RFC1918 plants as
    // non-OT, producing spurious findings_new/findings_resolved entries.
    let ot_subnets = ot_or_default(&user_ot_subnets);

    // Load and validate both scrub maps.
    let base_map_bytes =
        std::fs::read(&baseline_map_path).map_err(|source| OtError::InputOpen {
            path: baseline_map_path.clone(),
            source,
        })?;
    let base_map: ScrubMap = serde_json::from_slice(&base_map_bytes)?;
    base_map.validate()?;

    let curr_map_bytes = std::fs::read(&current_map_path).map_err(|source| OtError::InputOpen {
        path: current_map_path.clone(),
        source,
    })?;
    let curr_map: ScrubMap = serde_json::from_slice(&curr_map_bytes)?;
    curr_map.validate()?;

    // Parse both PCAPs.
    let base_obs = analyze(&baseline_pcap, &ot_subnets, false, None)?;
    let curr_obs = analyze(&current_pcap, &ot_subnets, false, None)?;

    // F-ADV-P4-010: validate map coverage of observed hosts. If the operator
    // swapped --baseline-map and --current-map, or supplied a stale map from
    // a different capture, `ip_to_pseudo` would fall back to
    // `unmapped_<hash>` for every host. The privacy invariant is preserved
    // (no real IPs leak via diff.rs) but utility is destroyed silently.
    // Warn loudly when coverage falls below 50%.
    {
        let report_coverage = |side: &str, obs: &crate::observe::Observations, map: &ScrubMap| {
            let observed: std::collections::HashSet<String> =
                obs.hosts.keys().map(|ip| ip.to_string()).collect();
            if observed.is_empty() {
                return; // nothing to check
            }
            let mapped_count = observed
                .iter()
                .filter(|ip| map.ips.values().any(|v| v == *ip))
                .count();
            let pct = (mapped_count as f64 / observed.len() as f64) * 100.0;
            if pct < 50.0 {
                eprintln!(
                    "WARNING (F-ADV-P4-010): only {pct:.1}% of {side} hosts are covered by \
                     --{side}-map ({mapped_count}/{} mapped). Did you swap --baseline-map and \
                     --current-map, or supply a stale map? The diff output's privacy is \
                     preserved but coverage is degraded — most hosts will appear as \
                     `unmapped_*` opaque labels.",
                    observed.len()
                );
            }
        };
        report_coverage("baseline", &base_obs, &base_map);
        report_coverage("current", &curr_obs, &curr_map);
    }

    // Run findings for each side.
    let base_findings = crate::findings::run_all(&base_obs, &ot_subnets);
    let curr_findings = crate::findings::run_all(&curr_obs, &ot_subnets);

    // Compute the diff using the user-supplied multiplier directly
    // (F-ADV-P1-002: post-filter was silently a no-op for values < 2.0).
    let diff = crate::diff::compute_with_multiplier(
        crate::diff::DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &base_findings,
        },
        crate::diff::DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &curr_findings,
        },
        flow_shift_multiplier,
    );

    // Render output based on file extension.
    let ext = output
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let content = match ext.as_str() {
        "json" => serde_json::to_string_pretty(&diff)?,
        "md" => format!(
            "# Diff (raw)\n\nFull rendering arrives in S-6.03.\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&diff)?
        ),
        _ => {
            // HTML placeholder; full rendering arrives in S-6.03.
            format!(
                "<!-- S-6.02 diff JSON; full HTML rendering arrives in S-6.03 -->\n<pre>{}</pre>\n",
                html_escape(&serde_json::to_string_pretty(&diff)?)
            )
        }
    };

    // F-ADV-P2-002: fail-closed leak detection on the rendered diff content
    // before write. The diff pipeline previously had NO ensure_clean gate
    // (asymmetric to the analyze --ai pipeline), so a mismatched / stale
    // scrub map would emit raw IPs straight into the JSON output via the
    // `unwrap_or(ip_str)` fallback in `ip_to_pseudo` (diff.rs). This pass
    // catches the residue before any write happens.
    crate::ai::leak_detector::ensure_clean(&content)?;
    crate::ai::leak_detector::ensure_no_map_values(&content, &base_map)?;
    crate::ai::leak_detector::ensure_no_map_values(&content, &curr_map)?;

    std::fs::write(&output, content).map_err(|source| OtError::WriteOutput {
        path: output.clone(),
        source,
    })?;
    eprintln!(
        "wrote {} ({} new hosts, {} gone, {} new findings, {} resolved)",
        output.display(),
        diff.hosts_new.len(),
        diff.hosts_gone.len(),
        diff.findings_new.len(),
        diff.findings_resolved.len(),
    );
    Ok(())
}

/// Escape `<`, `>`, and `&` for safe embedding in an HTML `<pre>` block.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

/// Run the heuristic classifier, apply any user-declared `--source-type`,
/// and emit the guard warning to stderr if the two disagree. Used by
/// every subcommand that classifies a capture (report / scrub / analyze).
fn classify_with_guard(
    obs: &crate::observe::Observations,
    declared: Option<SourceTypeArg>,
) -> crate::capture_source::Classification {
    let classification =
        crate::capture_source::classify(obs).with_declared(declared.map(Into::into));
    if let Some(warning) = classification.guard_warning() {
        eprintln!("WARNING: {warning}");
    }
    classification
}

/// Parse a PCAP and accumulate observations.
///
/// `progress` is the optional progress reporter introduced in S-5.01.
/// When `Some`, `record_packet` is called once per decoded packet so the
/// reporter can emit periodic progress lines.  The caller is responsible
/// for calling `reporter.finish()` after this function returns.
fn analyze(
    input: &std::path::Path,
    ot_subnets: &[IpNet],
    verbose: bool,
    mut progress: Option<&mut ProgressReporter<std::io::Stderr>>,
) -> Result<crate::observe::Observations> {
    let mut observer = Observer::new(ot_subnets.to_vec());
    let mut packet_count: u64 = 0;
    for pkt_result in iter_packets(input)? {
        let pkt = pkt_result?;
        if let Some(reporter) = progress.as_deref_mut() {
            reporter.record_packet(pkt.payload.len());
        }
        observer.observe(&pkt);
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

/// Derive the default audit-log path from the report output path:
/// `plant.html` → `plant.audit.json`. Used when `--ai` is set and
/// `--audit-log` is not explicitly overridden.
fn default_audit_log_path(output: &std::path::Path) -> PathBuf {
    let mut p = output.to_path_buf();
    p.set_extension("audit.json");
    p
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
    let mut reporter = ProgressReporter::new(std::io::stderr(), args.verbose);
    let obs = analyze(&args.input, &ot_subnets, args.verbose, Some(&mut reporter))?;
    reporter.finish();
    let classification = classify_with_guard(&obs, args.source_type);
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);

    // Two-pass scrub: render normally, then substitute every observed
    // identifier with a pseudonym. Keeps the data model unscrubbed (so
    // types stay pristine) and limits substitution to values we actually
    // saw, which avoids accidentally rewriting IP-shaped substrings in
    // unrelated text.
    //
    // S-6.01 (BC-5.03.001): when --baseline-map is supplied the merged map
    // is built via merge_map(baseline, &obs) rather than a fresh build_map.
    let map = if let Some(ref baseline_path) = args.baseline_map {
        let bytes = std::fs::read(baseline_path).map_err(|source| OtError::InputOpen {
            path: baseline_path.clone(),
            source,
        })?;
        let baseline: ScrubMap = serde_json::from_slice(&bytes)?;
        baseline.validate()?;
        merge_map(baseline, &obs)?
    } else {
        build_map(&obs)
    };
    let raw_md = render_markdown(
        &inventory,
        &findings,
        &obs,
        "<scrubbed>",
        Utc::now(),
        Some(&classification),
    )?;
    let md = scrub_text(&raw_md, &map);

    // F-ADV-P3-001: fail-closed leak detection on the scrubbed output
    // before write. The `scrub` subcommand is the manual "AI-safe" path
    // (users paste into Claude.ai / ChatGPT / Ollama); both `analyze --ai`
    // and `diff` apply the same gates. Without this check, a bug in
    // `scrub_text` would silently produce output containing real IPs/
    // MACs/hostnames — exactly the bytes the user is about to paste into
    // an external AI provider.
    crate::ai::leak_detector::ensure_clean(&md)?;
    crate::ai::leak_detector::ensure_no_map_values(&md, &map)?;

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

/// Print the scrubbed bytes to stderr and prompt the user for confirmation.
/// Returns `Ok(())` if the user answers "y" or "yes"; aborts with an error
/// for any other answer (including EOF).
fn review_scrub_gate(scrubbed: &str) -> Result<()> {
    eprintln!(
        "--- scrubbed prompt to claude ({} bytes) ---",
        scrubbed.len()
    );
    eprintln!("{scrubbed}");
    eprintln!("--- end scrubbed prompt ---");
    eprint!("Send to claude? [y/N]: ");
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|source| OtError::WriteOutput {
            path: "<stdin:review_scrub>".into(),
            source,
        })?;
    let trimmed = answer.trim().to_ascii_lowercase();
    if trimmed == "y" || trimmed == "yes" {
        Ok(())
    } else {
        Err(OtError::Parse("aborted by --review-scrub".to_string()))
    }
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
    let mut reporter = ProgressReporter::new(std::io::stderr(), args.verbose);
    let obs = analyze(&args.input, &ot_subnets, args.verbose, Some(&mut reporter))?;
    reporter.finish();
    let classification = classify_with_guard(&obs, args.source_type);
    let inventory = crate::inventory::build(&obs);
    let findings = crate::findings::run_all(&obs, &ot_subnets);
    let generated_at = Utc::now();

    // Always build the rules-based markdown — used both as the AI's
    // input (when --ai is on) and as the --md sidecar.
    //
    // F-ADV-P2-009: use the PCAP basename only, not the full path. The
    // full path can leak the operator's username, the plant name, embedded
    // IPs, and other privacy-sensitive identifiers — none of which the
    // scrub layer knows about because they're outside the parsed PCAP
    // bytes. The audit log (cli.rs:730-735) carries the SHA-256 for
    // chain-of-custody; the markdown only needs an identifier the
    // analyst recognises.
    let source_label = args
        .input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string());
    let raw_md = render_markdown(
        &inventory,
        &findings,
        &obs,
        &source_label,
        generated_at,
        Some(&classification),
    )?;

    // Without --ai, the only outputs are the HTML report + optional
    // --md / --json sidecars. Short-circuit.
    if !args.ai {
        let html = render_html(
            &inventory,
            &findings,
            &obs,
            &args.input.display().to_string(),
            generated_at,
            Some(&classification),
            None,
        )?;
        std::fs::write(&args.output, html).map_err(|source| OtError::WriteOutput {
            path: args.output.clone(),
            source,
        })?;
        write_optional_sidecars(&args, &raw_md, &inventory, &findings)?;
        eprintln!(
            "wrote {} ({} findings across {} hosts)",
            args.output.display(),
            findings.len(),
            inventory.len()
        );
        return Ok(());
    }

    // ---- --ai path: scrub → leak-check → invoke claude → unscrub → embed

    // F-ADV-P5-001: re-render the markdown with the AI sentinel as the
    // source label. The basename version of `raw_md` is retained for the
    // local sidecar (line ~763) and HTML report, where the operator
    // wants to see which capture this report came from. But the bytes
    // sent to the external AI provider must not carry the basename —
    // names like `acme-plant-alpha-line3-secret.pcap` embed plant /
    // line / facility identifiers that the scrub layer cannot detect
    // because they sit outside the parsed PCAP bytes.
    let raw_md_for_ai = render_markdown(
        &inventory,
        &findings,
        &obs,
        AI_INPUT_LABEL,
        generated_at,
        Some(&classification),
    )?;

    // 2. Mint pseudonyms and produce the scrubbed payload that will go
    //    to the AI.
    let map = build_map(&obs);
    let scrubbed_md = scrub_text(&raw_md_for_ai, &map);
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

    if args.review_scrub {
        review_scrub_gate(&user_message)?;
    }

    let model_label = args.model.clone().unwrap_or_else(|| "default".to_string());
    if args.verbose {
        eprintln!("  invoking claude (model: {})...", model_label);
    }
    // Pass verbose through to the provider so run_with_heartbeat knows
    // whether to emit heartbeat lines. The provider also checks
    // stderr.is_terminal() internally (AC-004), so explicit -v and
    // interactive TTY use cases are both covered.
    let provider = ClaudeCliProvider::new_verbose(args.model.clone(), args.verbose);
    let invoke_start = std::time::Instant::now();
    let scrubbed_response = provider.analyze(&system_prompt, &user_message)?;
    let elapsed = invoke_start.elapsed();

    // 5. Unscrub the AI response on this side of the boundary.
    let (unscrubbed_response, replaced, unmapped) = unscrub_text(&scrubbed_response, &map);
    if args.verbose {
        eprintln!(
            "  unscrubbing... {} pseudonyms replaced, {} unmapped",
            replaced,
            unmapped.len(),
        );
    }

    // 6. Render the AI's markdown response to safe HTML and embed in
    //    the report. pulldown-cmark with raw-HTML events filtered, so
    //    a Claude response containing `<script>` doesn't XSS whoever
    //    opens the report.
    let ai_html = crate::ai::html_render::render_safe(&unscrubbed_response);
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        &args.input.display().to_string(),
        generated_at,
        Some(&classification),
        Some(ai_html),
    )?;
    std::fs::write(&args.output, html).map_err(|source| OtError::WriteOutput {
        path: args.output.clone(),
        source,
    })?;

    // 7. Optional sidecars: markdown (combined: rules + AI), JSON,
    //    pseudonym map.
    if let Some(md_path) = &args.md {
        let mut combined = raw_md.clone();
        combined.push('\n');
        combined.push_str(&unscrubbed_response);
        combined.push('\n');
        std::fs::write(md_path, combined).map_err(|source| OtError::WriteOutput {
            path: md_path.clone(),
            source,
        })?;
    }
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
    if let Some(map_path) = &args.map {
        let map_json = serde_json::to_string_pretty(&map)?;
        std::fs::write(map_path, map_json).map_err(|source| OtError::WriteOutput {
            path: map_path.clone(),
            source,
        })?;
    }

    // 8. Audit log. Always written when --ai is on; the audit log is
    //    the privacy contract receipt. Path defaults to a `.audit.json`
    //    alongside the report output unless `--audit-log` overrides.
    //    The log itself passes through both leak checks before write
    //    — even though it only carries counts + hashes, treating it as
    //    suspect on write means a future field added carelessly can't
    //    bypass the invariant.
    let audit_path = args
        .audit_log
        .clone()
        .unwrap_or_else(|| default_audit_log_path(&args.output));
    let (size_bytes, sha256) = audit::sha256_file_hex(&args.input)?;
    let log = AuditLog {
        schema_version: audit::SCHEMA_VERSION,
        otsniff_version: crate::VERSION.to_string(),
        timestamp: generated_at,
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
        // S-5.03: augment pass is recorded separately. `None` until the
        // augment path is wired in Steps 3-4.
        augment_pass: None,
    };
    let log_json = serde_json::to_string_pretty(&log)?;
    leak_detector::ensure_clean(&log_json)?;
    leak_detector::ensure_no_map_values(&log_json, &map)?;
    std::fs::write(&audit_path, log_json).map_err(|source| OtError::WriteOutput {
        path: audit_path.clone(),
        source,
    })?;
    if args.verbose {
        eprintln!("  wrote audit log → {}", audit_path.display());
    }

    let unmapped_clause = if unmapped.is_empty() {
        String::new()
    } else {
        format!(", {} unknown left as-is", unmapped.len())
    };
    let map_clause = match &args.map {
        Some(p) => format!(", map saved to {}", p.display()),
        None => String::new(),
    };
    eprintln!(
        "wrote {} ({} pseudonyms unscrubbed{}{}, audit log → {})",
        args.output.display(),
        replaced,
        unmapped_clause,
        map_clause,
        audit_path.display(),
    );
    Ok(())
}

/// Shared sidecar writer used by the no-`--ai` short-circuit path.
fn write_optional_sidecars(
    args: &AnalyzeArgs,
    raw_md: &str,
    inventory: &[crate::inventory::Asset],
    findings: &[crate::findings::Finding],
) -> Result<()> {
    if let Some(md_path) = &args.md {
        std::fs::write(md_path, raw_md).map_err(|source| OtError::WriteOutput {
            path: md_path.clone(),
            source,
        })?;
    }
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
    Ok(())
}

fn run_unscrub(args: UnscrubArgs) -> Result<()> {
    let map_bytes = std::fs::read(&args.map).map_err(|source| OtError::InputOpen {
        path: args.map.clone(),
        source,
    })?;
    let map: ScrubMap = serde_json::from_slice(&map_bytes)?;
    // F-W1-001 (wave-1 adversarial review): mirror run_scrub's --baseline-map
    // path — validate the loaded map before any unscrub work. Rejects empty
    // pseudonym keys or empty real values that would silently corrupt output.
    map.validate()?;

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

    // F-ADV-P4-008: a common operator footgun is loading the wrong map
    // file. An empty map silently makes unscrub a no-op. Warn loudly to
    // stderr; promote to Err under --strict.
    if map.is_empty() {
        if args.strict {
            return Err(OtError::Parse(
                "F-ADV-P4-008: scrub map has zero entries (ips/macs/names all \
                 empty); unscrub would be a silent no-op. In strict mode this \
                 is an error — verify the --map path points to a populated map."
                    .to_string(),
            ));
        }
        eprintln!(
            "WARNING (F-ADV-P4-008): scrub map has zero entries; unscrub is a no-op. \
             Verify --map points to a populated map file. Re-run with --strict to \
             treat this as an error."
        );
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-005 regression-lockdown: ot_or_default(&[]) must return exactly
    /// the three IPv4 RFC1918 ranges — no IPv6, no extras, no missing.
    #[test]
    fn ot_or_default_empty_input_returns_only_ipv4_rfc1918() {
        let result = ot_or_default(&[]);
        assert_eq!(
            result.len(),
            3,
            "expected exactly 3 default OT subnets, got {}",
            result.len()
        );
        let expected: Vec<IpNet> = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            .iter()
            .map(|s| s.parse::<IpNet>().unwrap())
            .collect();
        assert_eq!(
            result, expected,
            "default OT subnets do not match the three RFC1918 ranges"
        );
        for net in &result {
            assert!(
                matches!(net, IpNet::V4(_)),
                "default OT subnet {} is not IPv4; AC-005 requires IPv4-only RFC1918 defaults",
                net
            );
        }
        assert_eq!(
            result.iter().filter(|n| matches!(n, IpNet::V6(_))).count(),
            0,
            "one or more default OT subnets are IPv6; AC-005 requires IPv4-only RFC1918 defaults"
        );
    }

    /// F-ADV-P5-001: the AI-bound markdown source label must be a constant
    /// sentinel that carries no operator-identifying tokens. The PCAP
    /// basename is BCSI under NERC CIP-011 — a name like
    /// `acme-plant-alpha-line3-2026-05-22.pcap` ships plant / line /
    /// facility identifiers into the AI provider's prompt that the
    /// scrub layer cannot detect or pseudonymize.
    #[test]
    fn f_adv_p5_001_ai_input_label_is_sentinel_not_basename() {
        // Contract: the constant exists and equals "<scrubbed>".
        assert_eq!(AI_INPUT_LABEL, "<scrubbed>");

        // Contract: the sentinel has no path-shape and no alphabetic
        // tokens an operator might use in plant / line / facility names.
        // Any sensitive basename token slipping into the constant would
        // immediately leak via the markdown header to the AI.
        for forbidden in [
            "acme", "plant", "line", "site", "facility", "secret", ".pcap",
        ] {
            assert!(
                !AI_INPUT_LABEL.contains(forbidden),
                "AI_INPUT_LABEL contains forbidden token '{forbidden}' — \
                 sentinel must be a constant, not a derived value"
            );
        }
    }

    /// F-ADV-P5-001 (cont.): rendering markdown with the AI sentinel as
    /// `input_label` must not embed any operator-identifying basename
    /// token in the output bytes. Test verifies the contract by rendering
    /// against an empty observation set and grepping for sensitive
    /// tokens. If the renderer ever starts embedding the input path
    /// elsewhere (e.g. a footer), this test catches it.
    #[test]
    fn f_adv_p5_001_render_with_ai_label_carries_no_basename_token() {
        use crate::report_md::render_markdown;
        use chrono::TimeZone;

        let obs = crate::observe::Observations::default();
        let inventory = crate::inventory::build(&obs);
        let findings: Vec<crate::findings::Finding> = Vec::new();
        let ts = chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap();

        let rendered = render_markdown(&inventory, &findings, &obs, AI_INPUT_LABEL, ts, None)
            .expect("render_markdown should succeed on empty fixture");

        for forbidden in [
            "acme-plant",
            "line3",
            "secret",
            "/Users/",
            "/home/",
            ".pcap",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "AI-bound markdown contains forbidden token '{forbidden}' — \
                 something other than input_label is leaking the path"
            );
        }
        assert!(
            rendered.contains(AI_INPUT_LABEL),
            "expected sentinel '{AI_INPUT_LABEL}' to appear in rendered markdown header"
        );
    }
}
