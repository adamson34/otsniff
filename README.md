# otsniff

One-shot OT-aware PCAP triage. Feed it a span-port capture, get a self-contained HTML report you can hand to a plant manager, IT director, or on-site engineer.

```sh
otsniff report plant-capture.pcap -o report.html
```

![otsniff demo](media/demo.gif)

## Why this exists

Every plant tour with a laptop and a SPAN port produces a PCAP. The existing options for analyzing it are:

- **Wireshark** — manual, expert-only, no findings layer.
- **Malcolm** (CISA/INL) — excellent but heavyweight: full Elasticsearch + Arkime + Logstash deployment, hours to stand up, not laptop-grade.
- **NetworkMiner** — file/credential carving, not OT-aware.
- **Vendor platforms** (Dragos, Nozomi, Claroty) — proprietary, ~$200k.

`otsniff` fills the gap: a single static binary that reads a PCAP and produces an exec-readable security report in seconds. No agents, no live capture, no Elasticsearch, no install fight. Optional: pipe through your local AI of choice — *without* sending real plant data anywhere, with a fail-closed leak detector and a per-run privacy audit log to prove it.

## What it finds

| Severity | Rule ID | What it catches |
|----------|---------|-----------------|
| Critical | `creds.{ftp,telnet,http_basic,snmp}` | Plaintext FTP / Telnet / HTTP-Basic / SNMPv1-v2c traffic |
| Critical | `egress.ot_to_internet` | Flows from configured OT subnets to public IPs |
| High     | `ics.modbus_writes` | Modbus engineering: write coil / register / mask write / diagnostic restart / force-listen-only |
| High     | `ics.cip_engineering` | EtherNet/IP CIP engineering services: Stop, Reset, Apply Attributes, Forward Close to controllers |
| High     | `ics.s7_engineering` | S7Comm engineering: PLC stop/start, block download/upload, password ops |
| High     | `compat.smbv1` | SMBv1 magic on tcp/445 or tcp/139 (EternalBlue / WannaCry protocol family) |
| Medium   | `compat.stale_tls` | SSL 3.0 / TLS 1.0 / TLS 1.1 ClientHellos |
| Medium   | `boundary.dns_resolver` | OT host querying DNS to a destination outside the OT zone |
| Medium   | `ot.unexpected_protocols` | AnyDesk, BitTorrent, IRC, OpenVPN, RTMP, SIP, SMTP on OT VLANs |

Plus an **asset inventory** (IP, hostname when DHCP names it, MAC, OUI vendor, inferred role: PLC / HMI / EWS / historian / IT) and a **comms-matrix** of top flows. The report also surfaces a **capture-source classification** (SPAN / host-side / TAP / ambiguous) — declarable explicitly via `--source-type` and guarded by the heuristic.

Every fired finding carries an **investigation playbook** with concrete next-actions tied to the actual evidence (hosts named, vendor-specific commands like `ipconfig /all` and Schannel registry paths, switch-CLI snippets), plus a **Detection criteria** line that explains in plain English what triggered the rule.

The full rule catalog with trigger conditions and external references (MITRE ATT&CK for ICS, CWE, RFC, vendor advisories) lives at [`docs/RULES.md`](docs/RULES.md). You can also print it locally without a PCAP:

```sh
otsniff rules            # markdown
otsniff rules --format json
```

### What that looks like on real captures

Run against the public 4SICS ICS Lab captures (with `--ot-subnet 10.10.10.0/24`):

| Capture | Hosts | Findings | Notable signals |
|---|---:|---:|---|
| 4SICS-GeekLounge-151020 (240K pkt) | 12 | 4 | OpenVPN tunnel from OT to public IP; cross-zone DNS resolver; S7 engineering |
| 4SICS-GeekLounge-151021 (1.2M pkt, 134 MB) | 47 | 8 | FTP / HTTP-Basic / Telnet plaintext, stale TLS, S7 engineering, internet egress |
| 4SICS-GeekLounge-151022 (2.3M pkt, 200 MB) | 99 | 10 | Modbus *and* S7 engineering, FTP / HTTP-Basic / SNMPv1 / Telnet plaintext, stale TLS, internet egress |

## Install

### One-liner (macOS, Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh
```

To pin a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh -s -- v0.3.0
```

Installs to `~/.local/bin/otsniff` by default; set `OTSNIFF_INSTALL_DIR=/usr/local/bin` (or wherever) to override. Verifies the SHA-256 checksum before installing. Read `--help` after install for the next step.

### From source

```sh
git clone https://github.com/adamson34/otsniff.git
cd otsniff
cargo install --path .
```

Requires Rust 1.85+.

### Pre-built binaries (manual)

[Releases page](https://github.com/adamson34/otsniff/releases) — static binaries for Linux x86_64, macOS x86_64/aarch64, and Windows x86_64. Download the `.tar.gz` for your target plus the `.sha256`, verify, extract, drop on `PATH`.

## Usage

```sh
# Standard HTML report:
otsniff report input.pcap -o report.html

# Tell the tool the capture provenance (recommended). Without it, a
# heuristic guesses; with it, the heuristic demotes to a guard and
# warns on stderr if your declaration disagrees with what the frame
# distribution looks like.
otsniff report input.pcap --source-type span -o report.html
otsniff report input.pcap --source-type host-side -o report.html
otsniff report input.pcap --source-type tap -o report.html

# Treat extra subnets as OT (in addition to the default RFC1918):
otsniff report input.pcap --ot-subnet 100.64.0.0/16

# Also emit findings + inventory as JSON:
otsniff report input.pcap --json findings.json
```

### AI-assisted triage

For when you want an AI to look at a capture but can't legally send raw plant data to an external API. `otsniff` replaces every IP, MAC, and DHCP-extracted hostname with stable pseudonyms before any AI sees the report, then unscrubs the AI's response on your machine. Vendor names, role labels, function-code labels, and protocol details pass through — that's the context the AI needs.

**Privacy contract.** The scrub layer is designed to align with **NERC CIP-011 (BES Cyber System Information)** handling principles and analogous frameworks like IEC 62443-3-3 / TSA pipeline directives / NIS2. A fail-closed leak detector sits between the scrub and the AI call: if any unscrubbed identifier survives, the run aborts before invoking the AI. See [`docs/audits/scrub-audit-cip011.md`](docs/audits/scrub-audit-cip011.md) for the field-by-field audit, plus [ADR-0006](docs/adr/0006-scrub-unscrub-pseudonyms.md) and [ADR-0007](docs/adr/0007-ai-via-claude-cli.md). Compliance certification is explicitly **not in scope** — see the [roadmap](docs/ROADMAP.md).

**Closed-loop, one command** — uses your local Claude Code CLI auth and subscription:

```sh
otsniff analyze plant.pcap -o report.md \
  --ot-subnet 10.10.10.0/24 \
  --source-type span \
  --map plant.map.json \
  --audit-log plant.audit.json \
  --verbose
```

Internally: scrub → fail-closed leak check (regex + map-value) → invoke `claude -p` → unscrub the response → append to `report.md`. The AI never sees real IPs, MACs, or hostnames at any point.

With `--verbose` the privacy ledger prints inline as it runs:

```
  scrubbing... 47 ip pseudonyms, 38 mac pseudonyms, 3 hostname pseudonyms
  leak check (regex): pass — 0 ipv4/ipv6/mac-shaped patterns found
  leak check (map-value): pass — 88 real values verified absent
  invoking claude (model: default)... done in 8.4s, 4127 bytes response
  unscrubbing... 14 pseudonyms replaced, 0 unmapped
```

With `--audit-log PATH`, the same data persists as a JSON chain-of-custody artifact — counts plus SHA-256 hashes of the exact bytes sent to and received from the provider. **No real identifiers in the log.** Useful evidence for a compliance reviewer that the scrub invariant held for a given run.

Requires the [Claude Code CLI](https://claude.com/code) installed and authenticated. Optional flags: `--model` (passthrough to `claude --model`), `--map PATH` (persist the pseudonym map for later unscrub of follow-up text), `--ot-subnet` (extra OT CIDRs).

**Manual flow, useful with any AI:**

```sh
# 1. Scrub: produces an LLM-safe markdown report + a local map.
otsniff scrub plant.pcap -o scrubbed.md --map plant.scrubmap.json

# 2. Paste scrubbed.md into Claude / GPT / your local model.

# 3. Unscrub: replace pseudonyms in the AI's response with real values.
otsniff unscrub --map plant.scrubmap.json ai-response.txt > final.txt
```

The map file is the only thing tying pseudonyms to real values — keep it where you'd keep the original PCAP. Without it, scrubbed output is `host_NNN` / `mac_NNN` / `name_NNN` references with no way back to a real network.

## Scope

**In scope:**

- Offline PCAP / PCAPNG analysis on Ethernet captures
- Modbus/TCP, EtherNet/IP, and S7Comm protocol awareness
- 12 rule-based findings (see table above and [`docs/RULES.md`](docs/RULES.md))
- Asset inventory with DHCP hostname extraction and OUI vendor inference
- Capture-source heuristic classification + explicit `--source-type` flag
- Scrub/unscrub pipeline + closed-loop AI triage via local `claude` CLI
- Per-run privacy audit log with chain-of-custody hashes

**Not in scope:**

- Live capture / agent / sensor mode (use Malcolm or a vendor platform)
- Detection rules, IDS alerting, dashboards (use Suricata / Zeek for the former)
- Full protocol decoding (function/service-code-level only)
- Compliance attestation — the project *aligns with* CIP-011 / IEC 62443 handling principles but does not certify
- DNP3, OPC-UA, BACnet, IEC-104 — see the [roadmap](docs/ROADMAP.md) for prioritization

## Testing with public PCAPs

We don't ship real plant PCAPs (NDA-laden). Public sources you can test against:

- [4SICS ICS Lab PCAPs](https://www.netresec.com/?page=PCAP4SICS) — what's used in the table above
- [ICS-pcap](https://github.com/automayt/ICS-pcap) — large community collection
- [ICSNPP test traces](https://github.com/cisagov/icsnpp) — bundled per-protocol

## Regenerating the demo GIF

The GIF at the top of this README is a recording of a real `otsniff` run. To regenerate after a UI change:

```sh
brew install vhs
# Drop the public 4SICS day-1 capture at media/demo.pcap
curl -L -o media/demo.pcap https://www.netresec.com/pcap/4SICS-GeekLounge-151020.pcap
vhs media/demo.tape
```

The recipe is in [`media/demo.tape`](media/demo.tape) — declarative, no Node, no npm. The input PCAP is gitignored; only the rendered GIF ships in the repo.

## Caveats

This is a **triage tool**, not an audit. Findings are heuristic. A clean report is not a green light — it means the SPAN port didn't show those particular things during the capture window. Validate with the on-site team before acting. The capture-source classifier (or your explicit `--source-type` declaration) mitigates one of the biggest sources of misinterpretation (treating a host-side `tcpdump` as if it were a SPAN), but doesn't eliminate the need for an operator who knows the network in the loop.

## Project layout

- [CLAUDE.md](CLAUDE.md) — architecture, conventions, and the project's design contract.
- [docs/RULES.md](docs/RULES.md) — auto-generated rule catalog with trigger conditions and external references.
- [docs/audits/scrub-audit-cip011.md](docs/audits/scrub-audit-cip011.md) — NERC CIP / IEC 62443 alignment audit.
- [docs/adr/](docs/adr/) — Architecture Decision Records.
- [docs/specs/](docs/specs/) — per-feature design specs (one per non-trivial feature). Every new feature spec includes a [scrub stance](docs/specs/scrub-stance-template.md).
- [docs/ROADMAP.md](docs/ROADMAP.md) — prioritized backlog, explicit non-goals, honest gaps.

## License

Apache-2.0.
