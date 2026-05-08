# otsniff

One-shot OT-aware PCAP triage. Feed it a span-port capture, get a self-contained HTML report you can hand to a plant manager, IT director, or on-site engineer.

```
otsniff report plant-capture.pcap -o report.html
```

## Why this exists

Every plant tour with a laptop and a SPAN port produces a PCAP. The existing options for analyzing it are:

- **Wireshark** — manual, expert-only, no findings layer.
- **Malcolm** (CISA/INL) — excellent but heavyweight: full Elasticsearch + Arkime + Logstash deployment, hours to stand up, not laptop-grade.
- **NetworkMiner** — file/credential carving, not OT-aware.
- **Vendor platforms** (Dragos, Nozomi, Claroty) — proprietary, ~$200k.

`otsniff` fills the gap: a single static binary that reads a PCAP and produces an exec-readable security report in seconds. No agents, no live capture, no Elasticsearch, no install fight. Optional: pipe through your local AI of choice — *without* sending real plant data anywhere.

## What it finds

| Severity | Finding | What it catches |
|----------|---------|-----------------|
| Critical | Plaintext credentials | FTP / Telnet / HTTP-Basic / SNMPv1/v2c traffic |
| Critical | Internet egress from OT subnets | Flows from RFC1918 OT ranges to public IPs |
| High     | Modbus engineering commands | Write coil / write register / diagnostic restart / force-listen-only |
| High     | EtherNet/IP CIP engineering services | Set Attribute, Reset, Start, Stop, Forward Open with config |
| High     | S7Comm engineering commands | Write Var, program download/upload, PLC start/stop |
| Medium   | Unexpected protocols on OT VLANs | SMTP, BitTorrent, SIP, OpenVPN, TeamViewer, AnyDesk |

Plus an **asset inventory** (IP, MAC, OUI vendor, inferred role: PLC / HMI / EWS / historian / IT) and a **comms-matrix** of top flows. The report also surfaces a **capture-source classification** (SPAN / host-side / TAP / ambiguous) so findings get interpreted correctly.

### What that looks like on real captures

Run against the public 4SICS ICS Lab captures:

| Capture | Hosts | Findings | Notable signals |
|---|---:|---:|---|
| 4SICS-GeekLounge-151020 (240K pkt) | 12 | 3 | OpenVPN tunnel from OT to public IP; DNS to non-OT resolver; S7 engineering |
| 4SICS-GeekLounge-151021 (1.2M pkt, 134 MB) | 47 | 19 | FTP / HTTP-Basic / Telnet plaintext, S7 engineering, internet egress |
| 4SICS-GeekLounge-151022 (2.3M pkt, 200 MB) | 99 | 21 | Modbus *and* S7 engineering, FTP / HTTP-Basic / SNMPv1 / Telnet plaintext, internet egress |

## Install

### One-liner (macOS, Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh
```

To pin a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh -s -- v0.2.0
```

Installs to `~/.local/bin/otsniff` by default; set `OTSNIFF_INSTALL_DIR=/usr/local/bin` (or wherever) to override. Verifies the SHA-256 checksum before installing. Reads `--help` after install for the next step.

### From source

```sh
git clone https://github.com/adamson34/otsniff.git
cd otsniff
cargo install --path .
```

Requires Rust 1.85+.

### Pre-built binaries (manual)

[Releases page](https://github.com/adamson34/otsniff/releases) — static binaries for Linux x86_64, macOS x86_64/aarch64, and Windows x86_64. Download the `.tar.gz` for your target plus the `.sha256`, verify, extract, drop on `PATH`.

### Coming soon

```sh
# Homebrew tap (planned)
brew install adamson34/tap/otsniff

# crates.io (planned)
cargo install otsniff
```

## Usage

```sh
# Standard HTML report:
otsniff report input.pcap -o report.html

# Treat extra subnets as OT (in addition to RFC1918):
otsniff report input.pcap --ot-subnet 100.64.0.0/16

# Also emit findings as JSON:
otsniff report input.pcap --json findings.json
```

### AI-assisted triage

For when you want an AI to look at a capture but can't legally send raw plant data to an external API. otsniff replaces every IP and MAC with stable pseudonyms before any AI sees the report, then unscrubs the AI's response on your machine. Vendor names, role labels, and protocol details pass through — that's the context the AI needs.

**Privacy contract.** The scrub layer is designed to align with **NERC CIP-011 (BES Cyber System Information)** handling principles and analogous frameworks like IEC 62443 / NIS2. A fail-closed leak detector sits between the scrub and the AI call: if any unscrubbed identifier survives, the run aborts before invoking the AI. See [ADR-0006](docs/adr/0006-scrub-unscrub-pseudonyms.md), [ADR-0007](docs/adr/0007-ai-via-claude-cli.md), and the explicit "not in scope: compliance certification" note in the [roadmap](docs/ROADMAP.md).

**Closed-loop, one command** — uses your local Claude Code CLI auth and subscription:

```sh
otsniff analyze plant.pcap -o report.md
```

Internally: scrub → fail-closed leak check → invoke `claude -p` → unscrub the response → append to `report.md`. The AI never sees real IPs or MACs at any point.

Requires the [Claude Code CLI](https://claude.com/code) installed and authenticated. Optional flags: `--model` (passthrough to `claude --model`), `--map PATH` (persist the pseudonym map for later unscrub of follow-up text), `--ot-subnet` (extra OT CIDRs).

**Manual flow, useful with any AI:**

```sh
# 1. Scrub: produces an LLM-safe markdown report + a local map.
otsniff scrub plant.pcap -o scrubbed.md --map plant.scrubmap.json

# 2. Paste scrubbed.md into Claude / GPT-4 / your local model.

# 3. Unscrub: replace pseudonyms in the AI's response with real values.
otsniff unscrub --map plant.scrubmap.json ai-response.txt > final.txt
```

The map file is the only thing tying pseudonyms to real values — keep it where you'd keep the original PCAP. Without it, scrubbed output is `host_NNN` references with no way back to a real network.

## Scope

**In scope:**

- Offline PCAP / PCAPNG analysis on Ethernet captures
- Modbus/TCP, EtherNet/IP, and S7Comm protocol awareness
- Findings + asset inventory in self-contained HTML or LLM-friendly markdown
- Capture-source heuristic classification (SPAN / host-side / TAP / ambiguous)
- Scrub/unscrub pipeline + closed-loop AI triage via local `claude` CLI

**Not in scope:**

- Live capture / agent / sensor mode (use Malcolm or a vendor platform)
- Detection rules, IDS alerting, dashboards
- Full protocol decoding (we only look at function/service codes used by findings)
- Compliance attestation — the project *aligns with* NERC CIP / IEC 62443 handling principles but does not certify
- DNP3, OPC-UA, BACnet, IEC-104 — see the [roadmap](docs/ROADMAP.md) for prioritization

## Testing with public PCAPs

We don't ship real plant PCAPs (NDA-laden). Public sources you can test against:

- [4SICS ICS Lab PCAPs](https://www.netresec.com/?page=PCAP4SICS) — what's used in the table above
- [ICS-pcap](https://github.com/automayt/ICS-pcap) — large community collection
- [ICSNPP test traces](https://github.com/cisagov/icsnpp) — bundled per-protocol

## Caveats

This is a **triage tool**, not an audit. Findings are heuristic. A clean report is not a green light — it means the SPAN port didn't show those particular things during the capture window. Validate with the on-site team before acting. The capture-source classifier mitigates one of the biggest sources of misinterpretation (treating a host-side `tcpdump` as if it were a SPAN), but doesn't eliminate the need for an operator who knows the network in the loop.

## Project layout

- [CLAUDE.md](CLAUDE.md) — architecture, conventions, and the project's design contract.
- [docs/adr/](docs/adr/) — Architecture Decision Records.
- [docs/specs/](docs/specs/) — per-feature design specs (one per non-trivial feature).
- [docs/ROADMAP.md](docs/ROADMAP.md) — prioritized backlog, explicit non-goals, honest gaps.

## License

Apache-2.0.
