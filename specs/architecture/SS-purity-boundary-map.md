---
artifact_type: architecture-shard
shard: purity-boundary-map
project: otsniff
traces_to: ARCH-INDEX.md
---

# Purity Boundary Map

Deterministic core (pure functions over typed inputs) vs effectful
shell (file I/O, subprocess, file writes). Approximately 80% of
LoC is pure.

## Pure core

These modules are pure functions — given the same inputs, produce
byte-identical outputs. No I/O, no clock reads (except where
`generated_at` is passed explicitly), no subprocess spawning.

| Module | LoC | Pure responsibility |
|---|---:|---|
| `src/parse/modbus.rs` | 151 | `&[u8] → Option<Pdu>` |
| `src/parse/enip.rs` | 164 | `&[u8] → Option<EnipHeader>` + `engineering_class_cip` |
| `src/parse/s7comm.rs` | 215 | `&[u8] → Option<Pdu>` |
| `src/parse/dhcp.rs` | 202 | `&[u8] → Option<DhcpInfo>` |
| `src/oui.rs` | 87 | `[u8; 6] → Option<&'static str>` + format_mac |
| `src/findings/plaintext_creds.rs` | 354 | `&Observations → Vec<Finding>` |
| `src/findings/engineering_commands.rs` | 412 | Same, takes `&[IpNet]` |
| `src/findings/internet_egress.rs` | 123 | Same |
| `src/findings/unexpected_protocols.rs` | 157 | Same |
| `src/findings/smbv1.rs` | 116 | Same |
| `src/findings/stale_tls.rs` | 155 | Same |
| `src/findings/dns_resolver.rs` | 137 | Same |
| `src/findings/mod.rs` | 173 | `run_all` + catalog + `host_label` |
| `src/inventory.rs` | 152 | `&Observations → Vec<Asset>` |
| `src/capture_source.rs::classify` | (most) | `&Observations → Classification` + `with_declared` |
| `src/scrub.rs` | 337 | All functions pure: `build_map`, `scrub_text`, `unscrub_text` |
| `src/ai/leak_detector.rs` | 200 | `ensure_clean`, `ensure_no_map_values`, `scan` |
| `src/ai/html_render.rs` | 93 | `render_safe(&str) → String` |
| `src/ai/prompts.rs` | 91 | Static strings + `system_prompt_for` |
| `src/audit.rs::sha256_hex` | (subset) | `&str → String` |
| `src/report.rs` | 199 | `render_html` (askama compile-time) |
| `src/report_md.rs` | 229 | `render_markdown` (std::fmt::Write) |
| `src/rule_catalog.rs` | 154 | `render_markdown` + `render_json` |
| `src/observe.rs::is_public` | (subset) | `IpAddr → bool` |

**Pure LoC total:** ~5,200 (roughly 80% of `src/`).

## Effectful shell

These modules do I/O, subprocess invocation, or other side effects.
They're confined to a small surface area.

| Module | LoC | Effects |
|---|---:|---|
| `src/main.rs` | 16 | stderr + process exit |
| `src/cli.rs` | 687 | File reads (PCAP), file writes (HTML, markdown, JSON, audit log, map), stderr, env-var reads, subprocess (via provider) |
| `src/pcap.rs` | 205 | File open + read (PCAP) |
| `src/ai/claude_cli.rs` | 101 | Subprocess spawn (`claude -p`); env (PATH, model arg passthrough) |
| `src/audit.rs::sha256_file_hex` | (subset of 211) | File read (streaming) |
| `src/observe.rs::Observer` | (mutable state) | Internal mutable state during observation; finalized by `finish()` |

**Effectful LoC total:** ~1,200 (roughly 18% of `src/`).

## Mutable state — confined to `Observer`

The single source of mutable state during a run is `Observer`. After
`Observer::finish()`, the resulting `Observations` is immutable and
flows to consumers. No other long-lived mutable state exists.

```
fn run_analyze(args: AnalyzeArgs) {
    let mut observer = Observer::new(ot_subnets);
    for pkt in iter_packets(&args.input)? {
        observer.observe(&pkt?);    // ← only mutating call site
    }
    let obs = observer.finish();    // ← state frozen here
    // ... downstream consumers all read from `&obs`
}
```

This boundary is what makes the privacy contract enforceable: the
scrub map is built from immutable `&Observations`; the leak detector
verifies against an immutable `&ScrubMap`; the AI sees only the
output of pure rendering + scrubbing.

## Determinism enforcement

Pure ≠ deterministic. Determinism additionally requires:

- **No `HashMap` iteration where order matters.** `BTreeMap` used for `Observations::hostnames`, `Observations::mac_frame_counts`, `ScrubMap::{ips,macs,names}`.
- **No `chrono::Utc::now()` inside pure functions.** Time is passed in as a parameter (`generated_at: DateTime<Utc>`) so snapshot tests can inject a fixed value.
- **Explicit `sort_by`** in every detector that builds evidence lists.
- **Pseudonym minting sorted by real value** in `scrub::build_map_at`.

## What this means for Phase 6 verification

The pure core is amenable to formal verification with Kani:
- Scrub round-trip (BC-5.01.003)
- Leak detector regex saturation (BC-5.02.001)
- Map-value substring check (BC-5.02.002)
- Composed privacy invariant (BC-5.02.003)
- AI HTML safe rendering (BC-6.01.001)

The effectful shell (`cli.rs`, `claude_cli.rs`, file I/O) is verified
by integration / sentinel tests, not Kani.

See `SS-verification-architecture.md` for the full plan.
