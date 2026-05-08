# otsniff roadmap

A living document. Status of each item: **done**, **in flight**, **planned**,
**proposed**, **blocked**, **dropped**.

Sizes: **S** ≤ 1 day, **M** 2–4 days, **L** ≥ a week.

This document is opinionated about *priority order* but not about *exact scope*
of any individual item — the spec for each lands in `docs/specs/` when it's
picked up.

---

## Released

- **v0.1.0** (tagged on `main`) — initial release. Pure-Rust PCAP triage,
  Modbus + EtherNet/IP, four findings (plaintext credentials, internet egress
  from OT, ICS engineering commands, unexpected protocols on OT VLANs),
  HTML + JSON output. See [GitHub releases](https://github.com/adamson34/otsniff/releases).

## On `develop` (unreleased, will land in the next stable cut)

- Scrub/unscrub for AI-assisted triage (ADR-0006)
- `analyze` subcommand — closed-loop scrub → Claude Code CLI → unscrub (ADR-0007)
- Capture-source heuristic detector + AI prompt qualifier
- Logical flow grouping (drops src_port from the flow key, tracks unique connections)
- S7Comm parser + new sub-finding under engineering-commands

When ready to ship, cut a release PR `develop → main`. Likely version: `0.2.0`
(or `0.3.0` if accumulated scope pushes us there). No tag pressure.

---

## Near-term (P0)

Things that visibly improve tomorrow's report on captures we already test
against. The 4SICS runs are the benchmark — a P0 item should change those
outputs in a way an OT defender would notice.

### P0-1: Finding dedup / rollup (S)

The 4SICS-22 output had 12 duplicate Telnet findings — one per destination
host. Same shape for FTP, HTTP-Basic, SNMPv1. Roll them up into one finding
per *kind* with destinations as evidence:

```
[Critical] Telnet observed (cleartext by definition)
12 hosts contacted on tcp/23. Credentials traversing these flows
should be considered exposed.
Evidence: 192.168.x.y, 192.168.x.z, ... (12 hosts)
```

**Why:** every busy capture today produces noise that drowns the real signal.
Single change to `findings/plaintext_creds.rs`. **Touches:** 1 file. **Deps:** none.

### P0-2: New rule-based findings (M)

Three findings that fire on data we already parse:

- **SMBv1 detection** — observable from SMB negotiate dialect 0x0202 in payload.
  Deprecated by Microsoft, banned by most enterprise policy, common in OT due
  to legacy HMIs.
- **Stale TLS versions** (TLS 1.0 / 1.1) — observable from ClientHello version
  field. Modern Windows blocks these by default; their presence on OT signals
  unsupported clients.
- **DNS to non-OT resolver** — boundary hygiene. Claude flagged this on the
  4SICS-20 run; a deterministic version catches it without an AI in the loop.

**Why:** each is small (~50–100 lines), each adds a real finding category we
miss today. Compounds the value-per-capture without expanding the protocol
surface. **Touches:** new modules under `findings/`, possibly new flow-label
recognizers in `observe.rs::classify_flow`. **Deps:** none.

### P0-3: Hostname / NetBIOS extraction + NERC-CIP-aware scrub (M)

Inventory becomes much more useful with hostnames. "PLC-LINE3" beats
"10.10.10.10" for an exec reading the report. Sources: DHCP option 12,
NetBIOS name service responses, mDNS PTR records.

**Compliance framing — load-bearing.** Hostnames that identify critical
assets fall under NERC CIP-011 (BES Cyber System Information). A name
like `ACME-SUB-LINE3-PLC` is BCSI even though `10.10.10.10` arguably is
not. The scrub support for hostnames is **not optional** — extracting
without scrubbing would actively make the AI flow worse from a
compliance posture, not better. Every hostname we extract goes into the
scrub map as a `name_NNN` pseudonym, and the leak detector gains a
hostname-shaped pattern check.

**Why:** asset inventory readability *and* required to keep the privacy
invariant honest as we extract more identifier types. **Touches:**
`observe.rs` (extraction), `scrub.rs` (new pseudonym class),
`inventory.rs` (display), `ai/leak_detector.rs` (extend regex). Updates
ADR-0006 to name CIP-011 as the framing reference. **Deps:** none.

### P0-4: NERC CIP / IEC 62443 scrub audit (M)

Systematic review of every field otsniff extracts or renders against
BCSI categories under NERC CIP-011 and analogous IEC 62443 / TSA
pipeline / NIS2 frameworks. Anything that could uniquely identify a
BES Cyber System or expose its operating characteristics goes into the
scrub map.

Items to audit (incomplete; the audit is the work):

- **Usernames** extracted from FTP USER, Telnet logins, HTTP Basic
  (b64-decoded). Operational account names like `ENGINEER1` or
  `OPERATOR-NIGHT` are BCSI. New pseudonym class: `user_NNN`.
- **Serial numbers** if we add EtherNet/IP Identity / BACnet Device
  Object decoding in the future. Pseudonym class: `serial_NNN`.
- **Firmware / vendor model strings** if extracted from protocol fields
  (ENIP Identity reply, Modbus device ID via fc=0x2B, S7Comm CPU info).
  These pinpoint specific firmware vulnerabilities — high BCSI value.
  Pseudonym class: `model_NNN`.
- **Modbus tag / S7 DB names** if we ever decode them. PLC tag naming
  conventions reveal operational logic. We don't extract these today
  but the rule should be: any new payload-aware finding has to declare
  what it scrubs before landing.

**Why:** the scrub layer is the project's load-bearing privacy claim.
Doing this audit now — and making it a repeatable process for new
features — is what lets us say "designed to align with BCSI handling"
honestly. Without it, the AI feature accumulates leak vectors as we
add more extractors.

**Touches:** `scrub.rs` (new pseudonym classes), `ai/leak_detector.rs`
(new patterns), `ai/prompts.rs` (system prompt extends to mention new
pseudonym vocabulary), ADR-0006 (regulatory framing), per-feature
specs (each declares its scrub stance).

**Deps:** none, but ideally lands together with or right after P0-3.

### P0-5: Source-type flag (CLI-recommended, heuristic as guard) (S)

`otsniff <subcommand> --source-type span|host-side|tap` becomes the
recommended way to declare capture provenance. The heuristic detector
demotes from "primary inference" to "guard": it runs on every capture
regardless of `--source-type`, and emits a warning when the user-
declared type disagrees with what the heuristic would have classified.

```
otsniff report capture.pcap --source-type span -o report.html
# (clean run)

otsniff report tcpdump.pcap --source-type span -o report.html
# WARNING: --source-type span declared, but heuristic suggests
# host-side (87% of frames involve MAC 70:71:BC:3A:0D:E8). Findings
# that depend on SPAN assumption (gateway inference, "no HMI seen")
# may be misleading. Re-run with --source-type host-side or
# investigate the capture.
```

**Why:** users typically know where the PCAP came from. Making them
say so is cheap; making the heuristic the default puts a guess in
the report's first line. The guard catches the "I thought this was
SPAN but it isn't" mistake.

**Touches:** `cli.rs` (flag), `capture_source.rs` (warning emission
when user-declared and heuristic disagree). **Deps:** none.

### P0-6: OUI table refresh (S)

The 4SICS captures had Siemens devices we mostly identified, but real plant
captures will have many vendors we don't. Curated subset of the IEEE OUI
registry (~3,000 OT-relevant entries) embedded as compressed data. v0.1
shipped with ~50 entries.

**Why:** vendor inference moves from "best guess on a hand-curated list" to
"works for any plant we'd realistically see." Trivial to ship, no ongoing
maintenance burden. **Touches:** `oui.rs` only. **Deps:** none.

---

## Mid-term (P1)

Items that expand reach or complete capability promises rather than improve
current outputs. Pick when P0 is empty.

### P1-1: DNP3 parser (M)

DNP3 over TCP/UDP 20000. Used by electric utilities and water/wastewater.
Same minimal-fidelity discipline as Modbus / ENIP / S7: function-code
recognition, engineering-class classification, no PDU-level decoding.

Engineering-class function codes to flag: Operate (4), Direct Operate (5),
Cold Restart (13), Warm Restart (14), Initialize Application (16), Initialize
Data (15), Save Configuration (24), Disable/Enable Unsolicited (20/21).

**Why:** opens utilities vertical. We have role inference for DNP3 already
(added during v0.1 testing) but no protocol awareness. **Caveat:** our only
DNP3 fixture is a fuzz test — we'd need a real-traffic capture to validate
quality. Worth verifying that one exists publicly before starting.

### P1-2: Better progress feedback (S)

`-v` mode currently emits one line at end-of-parse. For multi-GB captures the
user sees nothing for minutes. Periodic progress (every N packets, or every
10 MB read) would close that.

**Why:** quality of life on big captures. Cheap. **Touches:** `cli.rs`,
`pcap.rs`. **Deps:** none.

### P1-3: Dark-mode HTML report (S)

The HTML report currently has a single light theme. Add a
`prefers-color-scheme: dark` media query block (or a small toggle in the
header) so the report respects the reader's system theme. Self-contained
CSS, no JS dependency.

**Why:** the report is read on whatever the user's terminal / browser is
configured for. Light-only is jarring at night and out-of-place in any
dark-themed dashboard the user might embed the file in. ~30 lines of CSS
in `templates/report.html`. **Touches:** `templates/report.html` only.
**Deps:** none.

### P1-4: Tagged release of the develop accumulation (S)

Release PR `develop → main`, decide on version (probably 0.2.0), follow the
`/release` slash command. Then the four merged features (scrub, analyze,
capture-source, flow-grouping, S7Comm) ship as a coherent release.

**Why:** main is at v0.1.0 today, develop is 10+ commits ahead. The longer
this gap grows, the less useful main is. **Open question:** version number
and changelog framing.

---

## Backlog (P2)

Bigger swings. Pick deliberately, after at least one full P0 batch lands.

### P2-1: OPC-UA parser (L)

Modern unified architecture for OT/IT bridging. Binary OPC-UA over TCP/4840
is the most common, with much more complex framing than Modbus or S7.
Engineering-class operations: Write (service id 0x2BE), Call (0x2D8 — method
invocation, can do almost anything depending on the method), AddNodes
(0x4D2), DeleteNodes (0x4DC).

**Why:** OPC-UA is increasingly common in modern plants (anywhere TIA Portal
or Rockwell Studio 5000 is deployed in newer configs). **Caveat:** much more
complex than the protocols we've decoded so far. May be the first time we
need real chunked-message handling or session-state tracking.

### P2-2: BACnet parser (M)

Building automation. UDP/47808. Smaller spec than OPC-UA. Function codes:
WriteProperty, AtomicWriteFile, ReinitializeDevice, DeviceCommunicationControl.

**Why:** different vertical (HVAC / building management) from industrial.
Smaller user base for triage tools but also less competition. Worth doing if
a user asks; not a default.

### P2-3: Payload-aware findings (M)

Detect things in payload bytes the rule layer ignores today:
- Default credentials in cleartext (ftp anonymous, telnet admin/admin,
  Siemens default password "0000")
- HTTP basic auth with weak passwords (decode b64, check against a small
  watchlist)
- Suspicious DNS queries (dyn-DNS providers, IDN homoglyphs)
- Hard-coded modbus / S7 attack patterns (publicly-known PLC stuxnet-style
  sequences)

**Why:** adds depth to existing detector coverage. Each item is small but
together they meaningfully expand what otsniff finds. **Caveat:** moves us
toward "audit-grade" territory — false positives bite harder when the rule
references payload bytes.

### P2-4: AI-augmented detection layer (L)

LLM as a soft-detector alongside rules. The rules layer continues finding
deterministic things; an LLM pass over the observations adds fuzzy findings
("looks like a programming session," "byte profile is anomalous," "I don't
recognize this device"). Each soft finding includes the LLM's reasoning so
the user can validate.

**Why:** the most-different play in the original "AI powers" discussion.
Hardest to ship well — non-deterministic output, prompt engineering is real
work, false-positive risk is high in OT. Belongs after we have more rule
coverage to anchor against.

### P2-5: Multi-capture diff / temporal analysis (L)

`otsniff diff baseline.pcap suspect.pcap` — compare asset inventories and
findings between two captures of the same plant. Useful for "what changed
since last quarter's scan."

**Why:** unique to having a stable scrub map (so pseudonyms stay consistent
across runs). Powerful for change-detection workflows. Big design.

### P2-6: Web playground (L)

`otsniff.example.com` — upload a PCAP, get a report. Real engineering:
hosting, file-size limits, rate limiting, cost management, abuse vectors,
TOS. Defer until and unless there's a demonstrated need.

### P2-7: Native packaging (S each, M total)

Homebrew formula, Debian/RPM packages, scoop manifest. Requires a stable
release cadence to be worth automating. **Deps:** P1-3 (a stable v0.2.0 to
package).

### P2-8: Ollama local provider (M)

Second `AiProvider` implementation alongside `ClaudeCliProvider`. Shells
out to `ollama run <model>` with the same scrubbed input. Fulfills the
air-gap promise from ADR-0007 — analyze flow that doesn't require any
external service.

**Why P2 / not P1:** named as a v0.4 follow-on in ADR-0007 but no user
has asked for it yet, and the `claude` CLI integration covers the
majority of use cases. Move to P1 if a regulated entity surfaces who
literally cannot use any external AI service.

**Open question:** which local models are good enough for OT triage?
Probably qwen2.5-7b or llama3.1-8b at a minimum. Output quality varies.

---

## Explicitly not in scope

The project commits to *not* doing these. If user demand changes, we revisit
via an ADR — not a backlog item.

- **Live capture / sniffing.** otsniff reads PCAPs only. Live-capture mode
  would invite "agent" creep (always-on sensors with footprint, lifecycle,
  failure modes), competing with Dragos / Nozomi / Malcolm on their turf.
  PCAPs come from elsewhere.
- **Agent / sensor / always-on mode.** Same reasoning.
- **Vendor cloud integration / SaaS deployment.** otsniff is a local binary.
  No telemetry, no cloud API, no SSO. The one external touchpoint is the
  user's own AI of choice (`claude` CLI, Ollama).
- **Audit-grade certification.** Findings are heuristic. Useful for triage,
  not for compliance evidence. We'd need fundamentally different test
  infrastructure (real-PCAP corpus with labeled ground truth) to claim
  audit-grade, and that's a different product.
- **General-purpose / IT triage.** OT-focused — vendor inference, role
  classification, finding categories, AI prompts are all shaped for plant
  networks. An IT-focused fork is fine; merging IT scope into otsniff
  dilutes the OT thesis.
- **SIEM / IDS integration.** otsniff produces a report, not a stream of
  events for a SOC. The triage→report→action loop is the product, not
  alert-feeding.
- **Compliance certification.** otsniff is *designed to align* with
  NERC CIP-011 (BCSI handling), IEC 62443, NIS2, and similar
  frameworks — the scrub layer, leak detector, and per-feature scrub
  audit (P0-4) are all shaped by those principles. But the project
  does not undergo certification, does not produce attestation
  documents, and a clean otsniff report is *not* compliance evidence.
  Certification is a separate commercial process; we provide tools
  designed to be used by compliant programs, not the program itself.

---

## Honest gaps (known limitations, not backlog)

These are *named* limitations of the current tool — things to be honest about
in docs and to users, not pretend will be fixed by the next feature.

- **Heuristic, not audit-grade.** SNMP detection is a byte pattern, CIP
  service detection is a payload-window sweep, capture-source classifier is
  a MAC-distribution heuristic. False positives possible. Documented per-rule
  where it matters. A clean otsniff report is *not* an audit.
- **Limited protocol coverage.** Modbus + EtherNet/IP + S7Comm. ~70% of US
  industrial plants by install base, but not utilities (DNP3) or building
  automation (BACnet) or modern OPC-UA-only deployments.
- **Capture-source classification can be inconclusive.** Pre-filtered
  captures often classify as "ambiguous" — we report this honestly rather
  than guess. The override flag (P1-3) is the workaround.
- **No production deployment / real-user feedback loop.** Validated against
  the 4SICS lab captures and a couple of small fixtures. We don't know how
  the tool reads on a real plant capture from a real operator. Without that
  feedback the priority order in this roadmap is informed-guess, not
  evidence-based.
- **Privacy / compliance is best-effort, not certified.** The scrub
  layer + leak detector are designed to align with NERC CIP-011 BCSI
  handling and similar frameworks. They are *not* an attestation. A
  regulated entity that needs documented compliance must do their own
  audit and shouldn't rely on the tool's word for it. P0-3 and P0-4
  exist specifically to keep the alignment honest as the tool grows.
- **v0.x — semver not binding.** CLI shape, output format, and library API
  may all change before 1.0. Most recent example: subcommands replaced the
  flat CLI in v0.2.

---

## Decision log

Meta-decisions about how the project itself is run, separate from
architectural ADRs.

- **Cumulative develop, single release at a time.** No per-feature releases.
  Features land on `develop` continuously; `main` advances only at tagged
  releases. v0.2 / v0.3 conceptual milestones in commit messages were
  retired in favor of "develop accumulation → cut a release when it makes
  sense." (See conversation thread that preceded this roadmap.)
- **Branch + PR workflow.** Every non-trivial feature lands via
  `feat/<thing>` branch, PR to develop, squash-merge. Direct push to develop
  is reserved for one-line fixes. Matches the jira-cli pattern documented in
  CLAUDE.md.
- **Spec before implementation for non-trivial features.** `docs/specs/`
  files are written before the branch, not after. Forces a moment of
  "is this actually the right shape" before committing to code.
- **Roadmap items that get picked up gain a full spec.** This file is a list
  of intent; `docs/specs/<item>.md` is the design contract.
- **No version label inflation in commits.** Commits don't claim "v0.X
  feature" anymore — that ties the work to a specific release that may not
  ship that way. Just `feat:` / `fix:` per Conventional Commits.
