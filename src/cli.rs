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
use crate::findings::augmented::augment_findings;

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
use crate::pcap::iter_packets_multi;
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
    /// finding deltas, role inference shifts, and flow volume/rate shifts.
    /// Identification is by pseudonym from the merged scrub maps, so the
    /// comparison is stable across captures of the same network.
    //
    // Internal traceability: BC-9.05.001 (subcommand surface),
    // BC-3.08.001..003 (delta shape). See docs/ROADMAP.md P1-3.
    Diff(DiffArgs),
    /// Zonewarden segmentation-conformance tools (ADR-0013).
    #[command(subcommand)]
    Zonewarden(ZonewardenCmd),
}

#[derive(Subcommand, Debug)]
pub enum ZonewardenCmd {
    /// Draft a segmentation policy (zones + inferred Purdue levels) from a
    /// capture's asset inventory. Prints YAML to stdout — review it, add
    /// conduits, then pass it to `analyze --policy`.
    Suggest {
        /// Path to input PCAP/PCAPNG.
        input: PathBuf,
        /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
        #[arg(long = "ot-subnet", value_name = "CIDR")]
        ot_subnets: Vec<IpNet>,
    },
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Baseline capture (the "before" PCAP).
    pub baseline_pcap: PathBuf,
    /// Current capture (the "after" PCAP).
    pub current_pcap: PathBuf,
    /// Merged scrub map for the baseline capture.
    #[arg(long)]
    pub baseline_map: PathBuf,
    /// Merged scrub map for the current capture.
    #[arg(long)]
    pub current_map: PathBuf,
    /// Output report path (.html, .md, or .json).
    #[arg(short, long)]
    pub output: PathBuf,
    /// CIDR ranges to treat as OT zones (repeatable). Default: RFC1918.
    /// MUST match the value passed to `analyze` for the same captures, or
    /// the findings layer will classify hosts differently and produce
    /// spurious findings_new/findings_resolved entries (F-ADV-P1-001).
    #[arg(long = "ot-subnet", value_name = "CIDR")]
    pub ot_subnets: Vec<IpNet>,
    /// Ratio threshold for flow-shift detection — on per-second rates when both
    /// capture windows are usable, else raw bytes (default 2.0).
    /// A flow appearing in both captures is reported as a shift when
    /// the larger byte count is at least this multiple of the smaller.
    /// Values < 1.0 are rejected at parse time.
    #[arg(long, default_value_t = crate::diff::DEFAULT_FLOW_SHIFT_MULTIPLIER)]
    pub flow_shift_multiplier: f64,
    /// Path to a Zonewarden segmentation policy (YAML). When set, the same
    /// policy scores BOTH captures and the report gains a "Segmentation
    /// drift" section: conformance tally deltas, per-violation
    /// new/resolved/persisting, and the policy digest (P1-13). Omitting it
    /// leaves the diff unchanged.
    #[arg(long = "policy", value_name = "PATH")]
    pub policy: Option<PathBuf>,
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
    /// One or more input PCAP/PCAPNG files. Multiple files (e.g. a set of
    /// rotated captures) are ingested in command-line order and treated as
    /// one logical capture — append semantics, no timestamp re-sort
    /// (S-9.01). All files must share the same link-layer type.
    #[arg(value_name = "PCAP", num_args = 1.., required = true)]
    pub inputs: Vec<PathBuf>,
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
    /// Path to a Zonewarden segmentation policy (YAML). When set, otsniff
    /// classifies observed flows against the declared IEC 62443 zones/conduits
    /// (ADR-0013): the report gains a "Zonewarden — Segmentation Conformance"
    /// section and `zonewarden.*` findings, and the subnet-based
    /// `egress.ot_to_internet` rule is superseded by the engine.
    #[arg(long = "policy", value_name = "PATH")]
    pub policy: Option<PathBuf>,
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
        Command::Diff(a) => run_diff(a),
        Command::Zonewarden(ZonewardenCmd::Suggest { input, ot_subnets }) => {
            run_zonewarden_suggest(input, ot_subnets)
        }
    }
}

/// `otsniff zonewarden suggest` — draft a policy from the asset inventory.
fn run_zonewarden_suggest(input: PathBuf, ot_subnets: Vec<IpNet>) -> Result<()> {
    let ot_subnets = ot_or_default(&ot_subnets);
    let obs = analyze(std::slice::from_ref(&input), &ot_subnets, false, None)?;
    let inventory = crate::inventory::build(&obs);
    print!("{}", crate::segmentation::suggest::draft_policy(&inventory));
    Ok(())
}

/// Run the `diff` subcommand (AC-001 / BC-9.05.001).
///
/// Loads both PCAPs and their scrub maps, builds observations + findings for
/// each side, calls `crate::diff::compute`, and writes the result. For `.json`
/// outputs the `Diff` is serialized as pretty JSON. For `.html` and `.md`
/// outputs a placeholder is written — full rendering arrives in S-6.03.
fn run_diff(args: DiffArgs) -> Result<()> {
    let DiffArgs {
        baseline_pcap,
        current_pcap,
        baseline_map: baseline_map_path,
        current_map: current_map_path,
        output,
        ot_subnets: user_ot_subnets,
        flow_shift_multiplier,
        policy,
    } = args;
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

    // Parse both PCAPs. `diff` stays single-file per side (S-9.01 is
    // analyze-only); pass a 1-element slice to the generalized helper.
    let base_obs = analyze(
        std::slice::from_ref(&baseline_pcap),
        &ot_subnets,
        false,
        None,
    )?;
    let curr_obs = analyze(
        std::slice::from_ref(&current_pcap),
        &ot_subnets,
        false,
        None,
    )?;

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

    // Run findings for each side. P1-13: findings deliberately keep coming from
    // `run_all` (NOT `run_with_conformance`), so the existing finding deltas stay
    // policy-independent and comparable run to run. The segmentation-drift
    // section owns all conformance-derived output.
    let base_findings = crate::findings::run_all(&base_obs, &ot_subnets);
    let curr_findings = crate::findings::run_all(&curr_obs, &ot_subnets);

    // P1-13: when --policy is set, score BOTH captures against the SAME policy
    // (single-policy-held-constant) using the exact path `analyze --policy` uses.
    let (base_conf, curr_conf) = match &policy {
        Some(policy_path) => {
            let base_flows: Vec<crate::observe::FlowObs> =
                base_obs.flows.values().cloned().collect();
            let curr_flows: Vec<crate::observe::FlowObs> =
                curr_obs.flows.values().cloned().collect();
            let base_conf = crate::segmentation::run_conformance_path(policy_path, &base_flows)?;
            let curr_conf = crate::segmentation::run_conformance_path(policy_path, &curr_flows)?;
            (Some(base_conf), Some(curr_conf))
        }
        None => (None, None),
    };

    // Compute the diff using the user-supplied multiplier directly
    // (F-ADV-P1-002: post-filter was silently a no-op for values < 2.0).
    let diff = crate::diff::compute_with_multiplier(
        crate::diff::DiffInput {
            observations: &base_obs,
            map: &base_map,
            findings: &base_findings,
            conformance: base_conf.as_ref(),
        },
        crate::diff::DiffInput {
            observations: &curr_obs,
            map: &curr_map,
            findings: &curr_findings,
            conformance: curr_conf.as_ref(),
        },
        flow_shift_multiplier,
    );

    // S-11.01 (AC-003): surface a capture-window advisory on stderr. A
    // degenerate (missing / sub-second) window means ratios are raw byte
    // counts; a >= 2× (2×-or-more) mismatch means ratios are rate-normalized
    // but the windows are materially different. Windows differing by < 2×
    // print nothing.
    if let Some(warning) = diff.window_warning() {
        eprintln!("WARNING: {warning}");
    }

    // Render output based on file extension.
    let ext = output
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let content = match ext.as_str() {
        "json" => serde_json::to_string_pretty(&diff)?,
        "md" => crate::report_md::render_diff_markdown(&diff),
        _ => crate::report::render_diff_html(&diff)?,
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

/// S-10.01 AC-004: emit one `WARNING:` line per capture-window sanity finding,
/// mirroring `classify_with_guard`'s guard-warning emission. Always emitted
/// (not gated on `--verbose`) — a degenerate time base is a data-quality signal
/// the operator must see. A sane capture emits nothing.
fn emit_capture_warnings(obs: &crate::observe::Observations) {
    for warning in crate::capture_sanity::assess(obs) {
        eprintln!("WARNING: {}", warning.message());
    }
}

/// Parse a PCAP and accumulate observations.
///
/// `progress` is the optional progress reporter introduced in S-5.01.
/// When `Some`, `record_packet` is called once per decoded packet so the
/// reporter can emit periodic progress lines.  The caller is responsible
/// for calling `reporter.finish()` after this function returns.
fn analyze(
    inputs: &[PathBuf],
    ot_subnets: &[IpNet],
    verbose: bool,
    mut progress: Option<&mut ProgressReporter<std::io::Stderr>>,
) -> Result<crate::observe::Observations> {
    let mut observer = Observer::new(ot_subnets.to_vec());
    let mut packet_count: u64 = 0;
    for pkt_result in iter_packets_multi(inputs)? {
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

/// Basename (final path component) of a file, falling back to `<unknown>`.
/// F-ADV-P2-009: never emit a full path into a report/label/audit field.
fn basename_of(path: &std::path::Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Combined basename-only source label for a multi-file run (S-9.01 AC-005 /
/// F-ADV-P2-009). Comma-joins basenames, capped at the first 3 then
/// `… (+N more)` to keep large rotated sets readable in the report header.
fn multi_basename_label(inputs: &[PathBuf]) -> String {
    let names: Vec<String> = inputs.iter().map(|p| basename_of(p)).collect();
    if names.len() <= 3 {
        names.join(", ")
    } else {
        let head = names[..3].join(", ");
        format!("{head} … (+{} more)", names.len() - 3)
    }
}

/// Source string for the HTML report and JSON sidecar (S-9.01 AC-005).
///
/// **Single file:** the full path display — byte-identical to pre-S-9.01,
/// so existing single-file output never churns. **Multiple files:** the
/// basename-only combined label (no full path leaks).
fn html_source_label(inputs: &[PathBuf]) -> String {
    match inputs {
        [single] => single.display().to_string(),
        _ => multi_basename_label(inputs),
    }
}

/// Source label for the markdown report (S-9.01 AC-005).
///
/// **Single file:** the basename via `file_name()` — byte-identical to
/// pre-S-9.01. **Multiple files:** the basename-only combined label.
fn md_source_label(inputs: &[PathBuf]) -> String {
    match inputs {
        [single] => basename_of(single),
        _ => multi_basename_label(inputs),
    }
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
    let obs = analyze(
        std::slice::from_ref(&args.input),
        &ot_subnets,
        args.verbose,
        Some(&mut reporter),
    )?;
    reporter.finish();
    emit_capture_warnings(&obs);
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
            html_source_label(&args.inputs)
        );
    }
    let mut reporter = ProgressReporter::new(std::io::stderr(), args.verbose);
    let obs = analyze(&args.inputs, &ot_subnets, args.verbose, Some(&mut reporter))?;
    reporter.finish();
    emit_capture_warnings(&obs);
    let classification = classify_with_guard(&obs, args.source_type);
    let inventory = crate::inventory::build(&obs);

    // Zonewarden segmentation conformance (ADR-0013): only when --policy is set.
    // With a policy, findings come from the policy-aware path (which supersedes
    // the subnet-based egress rule) and the report gains the conformance section.
    let conformance = match &args.policy {
        Some(path) => {
            let flows: Vec<crate::observe::FlowObs> = obs.flows.values().cloned().collect();
            Some(crate::segmentation::run_conformance_path(path, &flows)?)
        }
        None => None,
    };
    let findings = match &conformance {
        Some(result) => crate::findings::run_with_conformance(&obs, &ot_subnets, result),
        None => crate::findings::run_all(&obs, &ot_subnets),
    };
    let conformance_html = conformance
        .as_ref()
        .map(crate::report::render_conformance_section);
    let conformance_md = conformance
        .as_ref()
        .map(crate::report_md::render_conformance_section_md);
    let generated_at = Utc::now();

    // Always build the rules-based markdown — used both as the AI's
    // input (when --ai is on) and as the --md sidecar.
    //
    // F-ADV-P2-009: use the PCAP basename only, not the full path. The
    // full path can leak the operator's username, the plant name, embedded
    // IPs, and other privacy-sensitive identifiers — none of which the
    // scrub layer knows about because they're outside the parsed PCAP
    // bytes. The audit log carries each file's SHA-256 for chain-of-custody;
    // the markdown only needs an identifier the analyst recognises. For a
    // multi-file run this is the capped basename-only combined label (S-9.01).
    let source_label = md_source_label(&args.inputs);
    let raw_md = render_markdown(
        &inventory,
        &findings,
        &obs,
        &source_label,
        generated_at,
        Some(&classification),
    )?;
    let raw_md = match &conformance_md {
        Some(section) => format!("{raw_md}\n{section}"),
        None => raw_md,
    };

    // Without --ai, the only outputs are the HTML report + optional
    // --md / --json sidecars. Short-circuit.
    if !args.ai {
        let html = render_html(
            &inventory,
            &findings,
            &obs,
            &html_source_label(&args.inputs),
            generated_at,
            Some(&classification),
            None,
            conformance_html.clone(),
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

    // 6. Run the AI augment pass (S-5.03 CRITICAL #1 — wire augment_findings).
    //
    // The augment pass runs a second LLM call with a different system prompt
    // (AUGMENT_PROMPT) to surface patterns the rule layer missed. It operates
    // on the same scrub map as the analyze pass, so pseudonyms are consistent
    // across both AI responses. Errors are soft-failures: the report renders
    // with rule findings and the analyze-pass AI section intact; the augmented
    // section is simply absent.
    let (augmented_findings, augment_summary_opt) =
        match augment_findings(&obs, &findings, &inventory, &provider) {
            Ok((af, summary)) => {
                if args.verbose {
                    eprintln!(
                        "  augment pass: {} findings ({} surviving dedup)",
                        summary.raw_finding_count, summary.surviving_finding_count
                    );
                }
                (af, Some(summary))
            }
            Err(e) => {
                // Soft-failure: log to stderr and continue without augmented findings.
                eprintln!("WARNING: augment pass failed (report will render without it): {e}");
                (vec![], None)
            }
        };

    // 7. Render the AI analysis section (analyze pass + augmented findings).
    //    pulldown-cmark with raw-HTML events filtered, so a Claude response
    //    containing `<script>` doesn't XSS whoever opens the report.
    //    The augmented section uses render_augmented_section which pipes
    //    AI-controlled text through render_safe internally.
    let ai_html = {
        let mut html_parts = crate::ai::html_render::render_safe(&unscrubbed_response);
        let augmented_section = crate::report::render_augmented_section(&augmented_findings);
        if !augmented_section.is_empty() {
            html_parts.push('\n');
            html_parts.push_str(&augmented_section);
        }
        html_parts
    };
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        &html_source_label(&args.inputs),
        generated_at,
        Some(&classification),
        Some(ai_html),
        conformance_html,
    )?;
    std::fs::write(&args.output, html).map_err(|source| OtError::WriteOutput {
        path: args.output.clone(),
        source,
    })?;

    // 8. Optional sidecars: markdown (combined: rules + AI + augmented), JSON,
    //    pseudonym map.
    if let Some(md_path) = &args.md {
        let mut combined = raw_md.clone();
        combined.push('\n');
        combined.push_str(&unscrubbed_response);
        combined.push('\n');
        // Append the augmented-findings markdown section when present.
        let augmented_md_section =
            crate::report_md::render_augmented_section_md(&augmented_findings);
        if !augmented_md_section.is_empty() {
            combined.push('\n');
            combined.push_str(&augmented_md_section);
        }
        std::fs::write(md_path, combined).map_err(|source| OtError::WriteOutput {
            path: md_path.clone(),
            source,
        })?;
    }
    if let Some(json_path) = &args.json {
        let payload = serde_json::json!({
            "version": crate::VERSION,
            "input": html_source_label(&args.inputs),
            "inventory": inventory,
            // S-12.01 AC-004: enrich each finding with its MITRE ATT&CK for ICS
            // techniques, looked up from the catalog by id (ADR-0014).
            "findings": crate::findings::findings_json(&findings[..]),
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

    // 9. Audit log. Always written when --ai is on; the audit log is
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
    // S-9.01 AC-004: one descriptor per input file, in CLI order. Each
    // `path` is a basename only (F-ADV-P2-009) and each `sha256` pins the
    // exact bytes ingested from that file (BC-7.01.002).
    let mut input_pcaps = Vec::with_capacity(args.inputs.len());
    for path in &args.inputs {
        let (size_bytes, sha256) = audit::sha256_file_hex(path)?;
        input_pcaps.push(InputDescriptor {
            path: basename_of(path),
            size_bytes,
            sha256,
        });
    }
    let log = AuditLog {
        schema_version: audit::SCHEMA_VERSION,
        otsniff_version: crate::VERSION.to_string(),
        timestamp: generated_at,
        input_pcaps,
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
        // S-5.03 AC-006: populate the augment_pass field from the returned summary.
        augment_pass: augment_summary_opt,
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
            "input": html_source_label(&args.inputs),
            "inventory": inventory,
            // S-12.01 AC-004: enrich each finding with its MITRE ATT&CK for ICS
            // techniques, looked up from the catalog by id (ADR-0014).
            "findings": crate::findings::findings_json(findings),
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

    /// S-9.01 AC-005: single-file source labels are byte-identical to the
    /// pre-S-9.01 expressions (HTML = full-path display, MD = basename), and
    /// the multi-file label is a basename-only join capped at 3 names then
    /// `… (+N more)` (EC-008). Locks the privacy-preserving format.
    #[test]
    fn source_labels_single_file_identical_and_multi_file_capped() {
        let one = [PathBuf::from("/srv/plant/caps/acme-line3.pcap")];
        // Single-file HTML == old `args.input.display().to_string()`.
        assert_eq!(
            html_source_label(&one),
            "/srv/plant/caps/acme-line3.pcap".to_string()
        );
        // Single-file MD == old basename via `file_name()`.
        assert_eq!(md_source_label(&one), "acme-line3.pcap".to_string());

        // Two/three files: plain comma-join of basenames (no path leak).
        let three: Vec<PathBuf> = ["/a/cap-01.pcap", "/b/cap-02.pcap", "/c/cap-03.pcap"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let label3 = md_source_label(&three);
        assert_eq!(label3, "cap-01.pcap, cap-02.pcap, cap-03.pcap");
        assert!(!label3.contains('/'), "multi-file label leaked a path");

        // Four+ files: first 3 names then `… (+N more)`.
        let five: Vec<PathBuf> = (1..=5)
            .map(|n| PathBuf::from(format!("/d/cap-{n:02}.pcap")))
            .collect();
        let label5 = html_source_label(&five);
        assert_eq!(label5, "cap-01.pcap, cap-02.pcap, cap-03.pcap … (+2 more)");
        assert!(!label5.contains("/d/"), "capped label leaked a path");
    }

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
