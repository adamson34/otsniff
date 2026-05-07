# otsniff

One-shot OT-aware PCAP triage. Feed it a span-port capture, get a self-contained HTML report you can hand to a plant manager, IT director, or on-site engineer.

```
otsniff plant-capture.pcap -o report.html
```

## Why this exists

Every plant tour with a laptop and a SPAN port produces a PCAP. The existing options for analyzing it are:

- **Wireshark** — manual, expert-only, no findings layer.
- **Malcolm** (CISA/INL) — excellent but heavyweight: full Elasticsearch + Arkime + Logstash deployment, hours to stand up, not laptop-grade.
- **NetworkMiner** — file/credential carving, not OT-aware.
- **Vendor platforms** (Dragos, Nozomi, Claroty) — proprietary, ~$200k.

`otsniff` fills the small gap in the middle: a single static binary that reads a PCAP and produces an exec-readable security report in seconds. No agents, no live capture, no Elasticsearch, no install fight.

## What it looks for (v0.1)

| Severity | Finding | What it catches |
|----------|---------|-----------------|
| Critical | Plaintext credentials | FTP / Telnet / HTTP-Basic / SNMPv1/v2c traffic |
| Critical | Internet egress from OT subnets | Flows from RFC1918 OT ranges to public IPs |
| High     | Modbus engineering commands | Write coil / write register / diagnostic restart / force-listen-only |
| High     | EtherNet/IP CIP engineering services | Set Attribute, Reset, Start, Stop, Forward Open with config |
| Medium   | Unexpected protocols on OT VLANs | SMTP, BitTorrent, SIP, OpenVPN, TeamViewer, AnyDesk |

Plus an **asset inventory** (IP, MAC, OUI vendor, inferred role: PLC / HMI / EWS / historian / IT) and a **top-flows** table.

## Install

### From source

```sh
cargo install --path .
```

Requires Rust 1.75+.

### Pre-built binaries

See the latest [release](https://github.com/example/otsniff/releases) — static binaries for Linux x86_64/aarch64, macOS, and Windows.

## Usage

```sh
otsniff input.pcap -o report.html

# Treat extra subnets as OT (in addition to RFC1918):
otsniff input.pcap --ot-subnet 100.64.0.0/16 --ot-subnet 198.18.0.0/15

# Also emit findings as JSON:
otsniff input.pcap --json findings.json
```

## Scope and non-goals

**In scope (v0.1):**

- Offline PCAP / PCAPNG analysis on Ethernet captures
- Modbus/TCP and EtherNet/IP protocol awareness
- Findings + asset inventory in self-contained HTML

**Not in scope:**

- Live capture / agent / sensor mode (use Malcolm or a vendor platform)
- Detection rules, IDS alerting, dashboards
- Full protocol decoding (we only look at function/service codes used by findings)
- DNP3, S7Comm, OPC-UA, BACnet, IEC-104 — coming in later versions if there's demand

## Testing with public PCAPs

We don't ship real plant PCAPs (NDA-laden). Public sources you can test against:

- [4SICS ICS Lab PCAPs](https://www.netresec.com/?page=PCAP4SICS)
- [ICS-pcap](https://github.com/automayt/ICS-pcap) — large community collection
- [ICSNPP test traces](https://github.com/cisagov/icsnpp) — bundled per-protocol

## Caveats

This is a **triage tool**, not an audit. Findings are heuristic. A clean report is not a green light — it just means the SPAN port didn't show those particular things during the capture window. Validate with the on-site team before acting.

## License

Apache-2.0.
