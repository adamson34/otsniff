# otsniff roadmap

A living document. Status of each item: **done**, **in flight**, **planned**,
**proposed**, **blocked**, **dropped**.

Sizes: **S** ≤ 1 day, **M** 2–4 days, **L** ≥ a week.

This document is opinionated about *priority order* but not about *exact scope*
of any individual item — the spec for each lands in `docs/specs/` when it's
picked up.

---

## Released

- **v0.5.0-dev** (in progress — HEAD of `develop`). VSDD wave-2/3 batch:
  - **Zonewarden segmentation module** ([ADR-0013](adr/0013-zonewarden-segmentation-module.md))
    — the standalone zonewarden tool folded in as a workspace sub-crate
    (`crates/zonewarden`, history-preserved, pure + Kani-verified). Adds
    IEC 62443 zone/conduit conformance with the Purdue-3.5 IDMZ
    no-bypass check, three `zonewarden.*` findings (egress deduped
    against the policy), a "Segmentation Conformance" report section
    with a deterministic `policy_digest`, `analyze --policy zones.yaml`,
    and `otsniff zonewarden suggest` to draft a policy from the asset
    inventory. The 7 segmentation Kani proofs run in `kani.yml`. Rule
    catalog now lists **23** rules.
  - **AI-augmented findings** (P0-8) — a second LLM pass anchored on
    the rules + inventory surfaces patterns the deterministic rules
    don't encode, each with a confidence + reasoning field, rendered in
    a separate section.
  - **Cross-capture diff** (P1-3) — `otsniff diff baseline.pcap
    current.pcap` reports host/finding/role/comms-matrix deltas across
    two runs, with HTML + markdown rendering and stable pseudonyms via
    merged maps.
- **v0.4.0** — VSDD wave-1 batch:
  - **Seven new detection rules** — every item from "Near-term rule
    additions" below now shipped at once (`creds.ldap_simple_bind`,
    `compat.ntlmv1`, `compat.weak_tls_cipher`, `creds.rdp_no_nla`,
    `boundary.ntp_external`, `recon.port_scan`,
    `ics.modbus_unit_id_sweep`). Rule catalog now lists **20** rules.
  - **DNP3 parser** (P1-1) — function-code classification with
    `ics.dnp3_engineering` finding.
  - **Privacy invariant formally verified** — six Kani harnesses cover
    the scrub round-trip and the IP/MAC shape detectors used by the
    fail-closed leak detector. Hand-rolled proof-models avoid `regex` /
    UTF-8 inside CBMC; all harnesses report `VERIFICATION:- SUCCESSFUL`.
  - **Mutation testing** wired with `cargo-mutants` and an 80% kill-rate
    gate in CI (compensating control for facade-mode stories).
  - **Tech-debt closure:** `ScrubMap::validate()` now rejects duplicate
    real-values (F-W1-003); leak-detector regexes wrapped in
    `LazyLock` (F-W1-004); `run_unscrub` validates corrupted maps
    eagerly (F-W1-001); pseudonym regex tightened to decimal-only
    (F-W1-002).
- **v0.3.1** — patch release: fix `Cargo.toml` repository URL,
  cover AI-flow artifacts in `.gitignore` (`*.map.json`, `*.audit.json`,
  `*.scrubbed.md`). No code change.
- **v0.3.0** — major release. CLI consolidation: `analyze` is the
  primary verb, `--ai` is the opt-in for the AI section, audit log
  auto-writes alongside. New detections (SMBv1, stale TLS, DNS
  resolver). Hostname extraction with NERC-CIP-aware scrub. Rule
  catalog with `otsniff rules` and `docs/RULES.md`. Privacy-ledger
  audit log. `--source-type` flag with heuristic-as-guard. Investigation
  playbooks per finding. Demo GIF + CIP-011 audit. Breaking: `report`
  subcommand removed (use `analyze`).
- **v0.2.1** — patch release adding `install.sh` curl-pipe-sh
  installer + repo URL fix. No binary changes vs. v0.2.0.
- **v0.2.0** — Scrub/unscrub for AI-assisted triage, `analyze`
  subcommand (Claude Code CLI integration), capture-source detector,
  logical flow grouping, S7Comm parser, plaintext-cred finding dedup.
- **v0.1.0** — initial release. Pure-Rust PCAP triage, Modbus +
  EtherNet/IP, four findings, HTML + JSON output.

See [GitHub releases](https://github.com/adamson34/otsniff/releases).

---

## Near-term (P0)

Things that visibly improve tomorrow's report on captures we already test
against. The 4SICS runs are the benchmark — a P0 item should change those
outputs in a way an OT defender would notice.

**Track 1 emphasis (next priority).** P0-7 (investigation playbooks)
shipped in v0.3; P0-8 (AI-augmented detection) shipped in the v0.5 dev
cycle (S-5.03). P0-6 (OUI refresh, #48/S-2.03), P0-9 (mDNS/NetBIOS
hostnames, #138/S-8.01), and P0-10 (multi-PCAP, #140/S-9.01) have all
shipped — **the P0 track is now fully delivered**. The next priorities
are the **P1** items below; the biggest *new* opportunity is
**segmentation drift** (P1-13 below),
which pairs the now-shipped cross-capture diff with the Zonewarden
engine.

### P0-1: Finding dedup / rollup (S) — ✅ shipped (v0.2)

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

### P0-2: New rule-based findings (M) — ✅ shipped (#27, v0.3)

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

### P0-3: Hostname / NetBIOS extraction + NERC-CIP-aware scrub (M) — ✅ shipped (#28, v0.3) — DHCP only; mDNS / NetBIOS deferred

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

### P0-4: NERC CIP / IEC 62443 scrub audit (M) — ✅ shipped (#29, v0.3)

The audit lives at `docs/audits/scrub-audit-cip011.md`. Systematic
walk of every field on `Observations` and every rendered surface
(HTML, markdown, JSON, AI-bound payload), classified against CIP-011
BCSI categories.

What landed:

- **Audit document.** Full field-by-field table (~30 rows) with
  current scrub stance, BCSI classification, and notes.
- **Process contract.** `docs/specs/scrub-stance-template.md` — every
  new feature spec must answer the four questions before landing.
- **Code lockdown.** `CredEvent.note` (the only High-BCSI field
  currently reachable via `Serialize`) marked `#[serde(skip)]` plus
  a sentinel test (`cred_event_note_must_not_reach_any_rendered_output`)
  that injects a canary username and asserts it doesn't reach HTML,
  markdown, scrubbed markdown, or JSON. Today it's in-memory only;
  the lockdown ensures it stays that way regardless of what future
  features do.
- **ADR-0006 amendment** linking to the audit and the template.

Items the audit identified as future work (not blockers, declared
when the relevant feature lands):

- `user_NNN` class — only when a feature actually surfaces extracted
  usernames (none today). The audit explicitly declines to add it
  preemptively.
- `serial_NNN` / `model_NNN` — same shape; needed only when ENIP
  Identity / BACnet Device Object / S7 CPU-info extraction lands.
- `tag_NNN` — needed only if we ever decode Modbus / S7 / OPC UA tag
  names, which we don't today.

Network-topology shape leakage and timestamp preservation were both
evaluated and accepted as documented trade-offs (see Findings #2 and
#4 in the audit). Vendor-name preservation is justified as Low-BCSI
(Finding #3).

**Why:** the scrub layer is the project's load-bearing privacy claim.
Doing this audit now — and making the scrub-stance template a
required section in every new spec — is what lets us say "designed
to align with BCSI handling" honestly. Without it, the AI feature
accumulates leak vectors as we add more extractors.

**Deps:** none, landed right after P0-3.

### P0-5: Source-type flag (CLI-recommended, heuristic as guard) (S) — ✅ shipped (#33, v0.3)

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

### P0-6: OUI table refresh (S) — ✅ shipped (#48, S-2.03)

The 4SICS captures had Siemens devices we mostly identified, but real plant
captures will have many vendors we don't. Curated subset of the IEEE OUI
registry (~3,000 OT-relevant entries) embedded as compressed data. v0.1
shipped with ~50 entries.

**Why:** vendor inference moves from "best guess on a hand-curated list" to
"works for any plant we'd realistically see." Trivial to ship, no ongoing
maintenance burden. **Touches:** `oui.rs` only. **Deps:** none.

### P0-7: Investigation playbooks per finding (M) — ✅ shipped (#26, v0.3)

Every Finding gains a structured playbook field — concrete next-action
steps tied to the actual evidence in that finding, not generic advice.

Today the `recommendation` field on each Finding is a static string:
*"Migrate the device(s) to SSH if supported, or place behind a jump
host."* Useful but generic — it doesn't reference the actual hosts in
question, the actual vendor, or the specific tools the on-site engineer
would use to act on it. The whole point of the tool is to save the
defender real time, and that means producing output an engineer can act
on without translation.

What this looks like for a finding like the Modbus engineering-commands
one on 4SICS-22 (`192.168.2.166` writing coils to three Moxa-OUI
controllers):

```
Investigation playbook:
  1. Identify 192.168.2.166 physically. The MAC is 28:CF:E9:18:B5:ED.
     Run `show mac address-table address 28cf.e918.b5ed` on the access
     switch to locate the port.
  2. Ask the on-shift control engineer whether 192.168.2.166 is the
     authorized Modbus master for these PLCs. If yes, this finding is
     expected; the host hygiene (telnet, ftp, smb open) is the issue.
  3. Pull session/event logs from the three Moxa devices. They'll show
     which Coil addresses were written — cross-reference against
     change-management tickets for the capture window.
  4. If 192.168.2.166 is not the authorized writer, do NOT block at the
     switch yet. Coordinate with operations — an unexpected ACL on a
     Modbus master is an availability event.
  5. After confirmation, ACL the switch port (or VLAN) so only the
     authorized SCADA host can reach tcp/502 on the controllers.
```

That's the kind of output that makes the rules-based report useful
*without* the AI flow being on, and that the AI flow then builds on
rather than reproducing.

**Why:** the rules-based report becomes valuable to an OT engineer who
hasn't installed `claude` and doesn't know what `analyze` is. The AI
flow becomes a multiplier on something already useful, instead of the
only path to useful output. Track 1's biggest single move.

**Touches:** every detector module under `src/findings/`. Each gets a
new `playbook: Vec<PlaybookStep>` field on `Finding`, with `PlaybookStep
{ action: String, references: Vec<EvidenceRef> }`. Renderers (HTML,
markdown, JSON) gain a Playbook section per finding. Snapshot tests
extend.

**Deps:** none functionally, but P0-2 (new findings) and P0-3
(hostname extraction) make the playbooks richer because there's more
specific evidence to reference. Order: land P0-7 first, then add
playbook content to new findings as they ship.

### P0-8: AI-augmented detection (M) — ✅ shipped (#114, S-5.03)

Second AI pass anchored on the rules-based findings. After
`run_all_findings()` produces the deterministic findings, an additional
`augment_findings()` call hands those findings *plus* the asset
inventory to the LLM and asks "what else do you see that the rules
missed, with confidence per item?"

Output: zero or more `AugmentedFinding` records. Each has the same
shape as a rules-based Finding plus `confidence: Low | Medium | High`
and `reasoning: String` (the LLM's chain-of-thought, exposed so the
user can validate). They render in a separate "AI-augmented findings"
section so a reader can see at a glance which are deterministic and
which are heuristic.

The 4SICS-22 demo run already showed Claude doing this work informally
in the AI section — flagging the role-inference misclassifications,
cross-referencing the same `192.168.2.166` across multiple findings,
spotting the gateway pattern from MAC sharing. Codifying that as a
structured second pass means the soft findings appear consistently and
can be referenced by ID, deduped across runs, and snapshot-tested.

**Why:** the rules layer doesn't cross-reference findings, doesn't
notice patterns the rules don't already encode, and doesn't critique
its own role inference. The AI pass does all three. Promoted from P2
because the existing AI prompt's quality demonstrates this works on
real data.

**Touches:** new `src/findings/augmented.rs` module. New AI provider
method (or shared method on `AiProvider`) for the second pass. Prompt
template committed and snapshot-tested. Renderers gain the new
section. The privacy invariant test extends to cover the augmented
prompt path.

**Deps:** P0-2 and P0-3 ideally land first — more rule findings and
hostname extraction mean richer anchors for the LLM's reasoning.
Doable in parallel with P0-7 since the entry points are different
detectors.

### P0-9: mDNS / NetBIOS / LLMNR hostname extraction (S) — ✅ shipped (#138, S-8.01)

Completes the deferred half of P0-3. Today we extract hostnames from
DHCP `Option 12 / Hostname` only. Mid-shop OT networks frequently have
no DHCP and lean on:

- **mDNS** (UDP/5353) — `_workstation._tcp.local`, vendor-specific
  service records like `_PROFINET-CBA._udp.local` on Siemens kit.
- **NetBIOS Name Service** (UDP/137) — `NBSTAT` queries reveal both
  the host's name and its workgroup, often the only label on legacy
  Windows engineering stations.
- **LLMNR** (UDP/5355) — Windows fallback, still common on engineering
  VLANs running domain-less workgroup setups.

**Why:** every finding currently rendered as `host_NNN (10.0.0.5)`
gains a real label when we observe just one mDNS/NBNS broadcast. The
defender goes from "who is `192.168.88.61`?" to "that's
`HMI-LINE-3 (192.168.88.61)`". Same UX win as P0-3's DHCP path
extended to captures that lacked DHCP entirely. **Touches:**
`observe.rs` (three small recognizers), `inventory.rs::Host::hostname`
already exists — just more code-paths populating it.
**Deps:** none.

### P0-10: Multi-PCAP / rotated-capture analyze (S) — ✅ shipped (#140, S-9.01)

`otsniff analyze a.pcap b.pcap c.pcap -o report.html` — concatenate
captures in CLI order, treat them as one logical capture, emit a
single report covering the union window.

**Why:** real plant captures rarely arrive as one file. `tcpdump -G`
and SPAN-port appliances both rotate by time or size; the operator
hands over `capture-2024-10-{01..07}.pcap`. Today the workaround is
`mergecap` from Wireshark, which is an extra tool, an extra step, and
leaves the user wondering whether timestamps survived the merge.
Native multi-file analyze removes that friction entirely.

**Touches:** `pcap.rs` (iterator chain over multiple files;
preserve per-file source attribution in the audit log), `cli.rs`
(positional arg becomes a `Vec<PathBuf>` with `min_values=1`).
**Edge case:** require captures share at least one common link-layer
type; refuse to merge `ethernet + linux-sll` etc. with an explicit
error. **Deps:** none.

---

## Mid-term (P1)

Items that expand reach or complete capability promises rather than improve
current outputs. Pick when P0 is empty.

### P1-1: DNP3 parser (M) — ✅ shipped (v0.4 wave-1)

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

### P1-2: Better progress feedback (S) — ✅ shipped (#73 S-5.01 parse progress, #74 S-5.02 claude heartbeat)

Two related UX gaps in `-v` mode:

1. **Parse loop is silent.** Currently emits one line at end-of-parse.
   For multi-GB captures the user sees nothing for minutes. Periodic
   progress (every N packets, or every 10 MB read) would close that.

2. **Claude invocation is silent.** With `--ai`, after printing
   "invoking claude (model: X)..." the user waits 10–60s with no
   output until Claude returns. The user can't tell if it's stuck.
   Lightweight fix: spawn the subprocess on a background thread and
   print a heartbeat from the main thread every ~3s:
   ```
   invoking claude (model: default)...
     [3s] still working...
     [7s] still working...
     done in 11.4s, 4127 bytes response
   ```
   ~30 LoC. The streaming-stdout alternative (`claude --output-format
   stream-json`) is more useful but couples us to a CLI output
   format and the privacy contract makes mid-stream display awkward
   (can't unscrub until the response completes, so partial tokens
   would still be in pseudonym form).

**Why:** quality of life on big captures and on AI invocations. Cheap.
**Touches:** `cli.rs`,
`pcap.rs`. **Deps:** none.

### P1-3: Cross-capture diff (M) — ✅ shipped (#107, #108, #119; S-6.02 + S-6.03)

`otsniff diff baseline.pcap suspect.pcap --baseline-map baseline.map.json
--current-map current.map.json -o diff.html`

Compares two captures of the same network and produces a delta:

- Hosts that appeared / disappeared
- Findings that are new vs. recurring vs. resolved
- Asset role changes (a host that was an IT endpoint now speaks
  Modbus, etc.)
- Comms-matrix shifts (new flow pairs, new ports, traffic-volume
  deltas above a threshold)

Requires stable pseudonyms across the two runs — the same real IP
must map to the same `host_NNN` in both maps. P0-3 (hostname
extraction with persistent maps) provides the foundation; cross-capture
diff is the user-facing payoff.

**Why:** "what changed since last quarter's scan?" is the highest-value
question an OT defender asks of repeat captures, and no current open-
source tool answers it cleanly. Once a customer has six months of
otsniff runs, switching to anything else throws away the longitudinal
view. Real network-effect lock-in.

**Touches:** new `src/diff.rs` module. New `diff` CLI subcommand. New
HTML/Markdown renderers (or extensions to existing). The scrub layer
gains a "merge maps" operation so pseudonyms are stable across new
captures of an existing network.

**Deps:** P0-3 (hostname extraction + persistent map operation).
Promoted from P2 in the Track 1 prioritization.

### P1-4: Prompt evaluation harness (S)

A small `tests/prompt-evals/` directory with committed expected-shape
outputs for the AI flow. Each eval is a (Observations fixture,
expected-shape rubric) pair — *not* an exact-string match (LLM output
is non-deterministic) but a structural rubric: "must contain a Priority
1 referencing host_001," "must qualify topology claims if capture
source is host-side," etc.

When a prompt changes, run the evals on the current Claude version,
compare results against the rubric, surface regressions before they
ship.

**Why:** prompt tuning becomes "discipline" instead of "vibes." Without
this, every prompt change is uncovered — we'd find out about
regressions only when a real user noticed the AI got worse.

**Touches:** new directory `tests/prompt-evals/`, new test harness in
`tests/`, possibly a `cargo xtask eval-prompts` runner that supports
the non-deterministic LLM testing pattern.

**Deps:** none.

### P1-5: Tagged release of the develop accumulation (S) — ✅ recurring

**Status:** Done through v0.3.1 (current). Kept in roadmap as a
recurring discipline — the `release/v0.X.Y` branch + `develop → main`
PR + tag flow runs after every meaningful develop accumulation. See
`.claude/commands/release.md` for the current playbook.

### P1-6: MITRE ATT&CK for ICS technique mapping (M)

Every `Finding` gains a `technique_ids: Vec<MitreId>` field
referencing the [ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
matrix — concrete `T0815` (Denial of View), `T0853` (Scripting),
`T0859` (Valid Accounts), `T0866` (Exploitation of Remote Services)
identifiers per finding. Renderers (HTML, markdown, JSON) surface the
IDs with anchors back to the MITRE site.

**Why:** "engineering-class CIP write" is otsniff's framing; "T0831
Manipulation of Control" is the framing every blue-team playbook
already uses. Mapping our findings into that taxonomy meets defenders
where they already think and makes our output paste-able directly
into an IR ticket. Several recently-shipped rules (`ics.modbus_writes`,
`creds.rdp_no_nla`, `recon.port_scan`) have obvious one-to-one
technique mappings; others (`compat.stale_tls`) map less cleanly and
get tagged as "supports T-XXXX" rather than asserting fire-equals-
technique. **Touches:** `findings/mod.rs` (`Finding` schema), each
detector module (one-line tag), rendering layer, snapshot tests.
**Deps:** none.

### P1-7: PCAP slicing — extract subset that triggered a finding (M)

`otsniff slice <PCAP> --finding F-001 -o filtered.pcap` — produce a
much smaller PCAP containing only the packets that contributed to
finding `F-001`. Plus `--host 192.168.88.52` and `--flow A→B:502`
variants.

**Why:** today, when otsniff flags a Modbus write, the operator still
opens the original (potentially gigabyte-sized) PCAP in Wireshark to
investigate. A pre-sliced PCAP loads instantly, contains only the
relevant packets, and is small enough to attach to a ticket or share
with a vendor for support. Closes the loop with the
deeper-investigation tools that already exist (Wireshark, tshark,
zeek) rather than competing with them. **Touches:** new `slice`
subcommand, packet-index threading through the observer (which packet
contributed to which event), `pcap.rs` write-half. **Deps:** small
refactor to retain `pcap_offset: u64` on `CredEvent` / `ModbusEvent`
etc. so we know which bytes to write out.

### P1-9: Capture-window sanity warning (S) — ✅ shipped (#143, S-10.01)

Surface explicit warnings when the input PCAP has degenerate timestamps —
all-zero (epoch 1970), entire capture window <1s, or non-monotonic
ordering. Discovered while triaging real captures (May 2026): both
`iFix_Server119.pcap` and `MicroLogix56.pcap` ship with all-zero
timestamps; the tool happily processes them but any time-based
analysis (capture-source heuristic, flow rate, port-scan window) is
meaningless on those inputs. Currently silent.

**Why:** users see "Capture window: 1970-01-01 00:00:00 UTC →
1970-01-01 00:00:00 UTC" in the summary section but get no signal
that downstream findings may be unreliable as a result. A one-line
WARNING in the report header + verbose stderr message would close
the gap.

**Touches:** `observe.rs` (already tracks min/max timestamp),
`report.rs` + `report_md.rs` (add a banner), `cli.rs` (stderr warn).
**Deps:** none.

### P1-10: Spoofed-source detection / inventory cap (M)

DoS captures (ping flood, SYN flood) produce inventories with 10k+
"hosts" because attacker tooling spoofs source IPs. Discovered while
triaging the Lemay/Fernandez dataset: `eth2dump-pingFloodDDoS` and
`eth2dump-tcpSYNFloodDDoS` show 12,005 / 12,017 hosts each — the
report inventory becomes unreadable.

Two-part fix:

1. **Detector** — new `attack.spoofed_sources` finding that fires
   when K hosts (K > 500) appear with: exactly 1 packet sent, no
   responses received, no MAC observation, no protocol enrichment.
   That's the spoofed-source fingerprint.

2. **Inventory render cap** — when inventory > 100 hosts, paginate
   or summarize. Top-N by traffic + "+ K low-volume hosts (likely
   spoofed) summarized" footer.

**Why:** correctness (the 12k entries are technically real distinct
src IPs, but reporting them as "hosts" misleads the analyst) and UX
(the HTML report becomes unusably large).

**Touches:** new `findings/spoofed_sources.rs`, `report.rs` +
`report_md.rs` inventory section, snapshot tests.
**Deps:** none.

### P1-11: Diff capture-window normalization (S) — ✅ shipped (#145, S-11.01)

`otsniff diff` flow-shift detection currently compares raw byte
counts. When the two captures cover different durations (e.g. 1h
baseline vs 30min current), every steady-state flow gets reported
as a "shift" with ratio ≈ duration_ratio (2.0 for the 30m/1h pair).
These are duration artifacts, not behavioral changes.

Two options:

1. **Compute and surface bytes/sec ratio** alongside bytes ratio.
   Threshold on rate-normalized values rather than raw.

2. **Warn loudly** when the two capture windows differ by >2x,
   citing which results are likely duration-artifact rather than
   real shifts.

**Why:** discovered while running the wave-2 diff demo on real
captures. Without this, every diff between recordings of unequal
duration produces noise that dilutes real signals. Pre-empts a
common operator footgun.

**Touches:** `diff.rs::compute` (rate normalization), `cli.rs`
(window-mismatch warning), snapshot tests.
**Deps:** P1-3 base diff (shipped).

### P1-12: Trusted-writer / engineering-allowlist suppression (M)

Today the `ics.modbus_writes` (and analogous `ics.s7_engineering`,
`ics.cip_engineering`) rules fire on every engineering-class call,
forcing the analyst to read the playbook step "ask the on-shift
control engineer whether X is the authorized Modbus master." On
captures where the same trusted EWS → PLC pair makes thousands of
writes, the rule fires once but the noise floor is high.

Add a `--trusted-writer SRC=DST:PROTO` repeatable flag (or YAML
config) that suppresses or downgrades findings for pre-declared
authorized pairs:

```
otsniff analyze plant.pcap \
  --trusted-writer 10.20.0.5=10.20.0.10:modbus \
  --trusted-writer 10.20.0.5=10.20.0.11:modbus
```

Findings still appear (visibility preserved) but with severity
INFO instead of HIGH, and a "matched trusted-writer rule" badge.

**Why:** real plants have well-known authorized writer hosts.
Without an allowlist, the engineering-commands rule is technically
correct but reduces the signal-to-noise ratio of repeat scans.
This is the highest-impact "false positive in production
deployments" gap discovered in May 2026 triage.

**Touches:** new config layer in `cli.rs`, `findings/engineering_commands.rs`
(per-finding suppression hook), snapshot tests.
**Deps:** none.

### P1-13: Segmentation drift (M) — ✅ shipped

`otsniff diff baseline.pcap current.pcap --policy zones.yaml` (or a
dedicated `--segmentation-drift` mode) compares the *Zonewarden
conformance verdict* across two captures of the same network rather
than just the raw flow set:

- Conformance-tally deltas (allowed / intra-zone / violations /
  bypasses up or down vs. baseline).
- Newly-violating flows (conformant last quarter, violating now) and
  newly-resolved ones — the segmentation analog of P1-3's
  new/recurring/resolved finding classification.
- `policy_digest` equality check — if the digests match, the *policy*
  is unchanged and every delta is a behavioral change; if they differ,
  flag that the comparison crosses a policy revision.

**Why:** "did our segmentation posture regress since last quarter's
scan?" is the highest-value longitudinal question for a 62443 program,
and it falls straight out of pairing two features that just landed
(cross-capture diff, P1-3 ✅; Zonewarden conformance, ADR-0013 ✅).
Neither feature answers it alone. The deterministic `policy_digest`
makes the "is this a real drift or just a re-authored policy?"
distinction rigorous rather than guessed.

**Touches:** `diff.rs` (segmentation-aware comparison), the diff
renderers, `cli.rs` (`--policy` on `diff`), snapshot tests. Likely
warrants its own ADR or spec. **Deps:** P1-3 (shipped), ADR-0013
(shipped).

### P1-8: IOC matching against curated OT threat-intel feeds (M)

Embedded offline database of OT-relevant IOCs (IPs, domains, file
hashes, JA3/JA3S fingerprints). Sources: [CISA ICS-CERT advisories](https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A95),
Dragos public WorldView IOC samples, Talos public IOC dumps. New
`threat.known_bad` finding fires when an observed identifier matches.

**Why:** otsniff is positioned as a triage tool, not a SIEM — but
"have we already seen this IP in a CISA advisory" is a question the
defender will ask of every output, and answering it offline (no
network call, no telemetry, no API key) fits the deploy model. Update
cadence is per release — the DB ships embedded, just like the OUI
table. **Touches:** new `threat/` module with the compressed DB,
new detector `findings/known_bad.rs`, build-time data ingestion
script. **Deps:** P0-6 (OUI table refresh) is the same pattern at
smaller scale — share infrastructure.

---

## Shipped in v0.3 without prior roadmap entries

These landed during the v0.3 cycle without a P0/P1 slot but are worth
documenting so the trajectory is recoverable from this file alone.

### Rule catalog — ✅ shipped (#30)

Every detector now carries a `RuleMetadata` block (id, plain-English
trigger, data sources, MITRE/CWE/RFC/vendor references). Surfaces:

- `otsniff rules [--format md|json]` — print the catalog without a PCAP
- [`docs/RULES.md`](RULES.md) — auto-generated, kept in sync by a test
  that fails the build if it drifts
- "Detection criteria" line inline in HTML and markdown reports under
  each fired finding

Sentinel tests ensure every detector has metadata and every fired
finding id appears in the catalog.

### Privacy-ledger audit log — ✅ shipped (#31)

When `--ai` is on, a JSON chain-of-custody artifact writes alongside
the report (default path: `<report-stem>.audit.json`). Contains scrub
counts, leak-check verdicts, SHA-256 hashes of the exact bytes sent to
and received from the AI — no real identifiers. Override path with
`--audit-log <PATH>`.

### Hostnames in finding evidence — ✅ shipped (#32)

Evidence lines render `LINE-3-PLC (10.10.10.10)` instead of bare IPs
when DHCP told us a hostname. Degrades cleanly to just the IP on
captures without DHCP. Threaded through every detector via a shared
`host_label(ip, obs)` helper.

### CLI unification — ✅ shipped (#35, breaking change)

The `report` subcommand was folded into `analyze`. `analyze` is now
the primary verb: rules-based HTML by default, `--ai` is the opt-in
for the AI section. Audit log auto-writes when `--ai` is on.
`scrub` / `unscrub` remain as advanced subcommands for users driving
their own AI (Claude.ai web, ChatGPT, local Ollama).

Migration: `report` → `analyze`; old `analyze` (AI-only) → `analyze --ai`.

---

## Near-term rule additions — ✅ all shipped in v0.4 wave-1

This batch was originally five to seven rules sized at ~80 LoC each.
All seven landed in the VSDD wave-1 batch; the rule catalog grew from
13 → 20. Section preserved as a historical record of the proposal
shape; each entry below is now annotated with its shipped state.

### `creds.ldap_simple_bind` (S) — ✅ shipped

LDAP `BindRequest` with `SimpleAuthentication` over plaintext LDAP
(TCP/389, no STARTTLS). Fires on real captures more often than
expected — small IT shops still ship default Windows AD without TLS.
**Touches:** `observe.rs` LDAP recognizer, new `findings/ldap_creds.rs`.

### `compat.ntlmv1` (S) — ✅ shipped

NTLMv1 authentication. Dictionary-attackable. Observable from the
NTLMSSP NEGOTIATE message's flags field. **Touches:** SMB / HTTP path
recognizers in `observe.rs`, new `findings/ntlmv1.rs`.

### `compat.weak_tls_cipher` (S) — ✅ shipped

TLS ClientHello listing RC4, DES, 3DES, or NULL cipher suites.
Parallel to `compat.stale_tls`, narrower angle. **Touches:**
`observe.rs::observe_tcp` (extend ClientHello parsing to capture
cipher list), new `findings/weak_tls_cipher.rs`.

### `creds.rdp_no_nla` (S) — ✅ shipped

RDP connection negotiated without Network Level Authentication.
Visible in the X.224 / TPKT connection-confirm packet's RDP_NEG
flags. **Touches:** `observe.rs` RDP recognizer, new
`findings/rdp_legacy.rs`.

### `boundary.ntp_external` (S) — ✅ shipped (S-2.09, PR #65)

OT host syncing time to a public NTP server. Parallel to
`boundary.dns_resolver` — same cross-zone filter shape on UDP/123.
**Touches:** new `findings/ntp_external.rs`.

### `recon.port_scan` (M) — ✅ shipped

Same source IP talking to many distinct destinations on the same
port within the capture window. Implementable as a detector over
existing `Observations::flows`, no new observer state needed.
Threshold: ≥ 5 distinct destinations to start; tunable later.
**Touches:** new `findings/recon_scan.rs`.

### `ics.modbus_unit_id_sweep` (M) — ✅ shipped

Same Modbus client iterating across many unit IDs. Classic Modbus
discovery / fuzzing pattern. **Touches:** `observe.rs` to track unit
ID per (src, dst) pair on modbus events, new
`findings/modbus_recon.rs`.

**Sequence (historical):** all seven landed inside the VSDD wave-1
delivery without serializing — the per-story TDD discipline let them
proceed in parallel. The originally-planned ordering (four `S` rules
first, then `recon.port_scan`, then `ics.modbus_unit_id_sweep` last)
turned out not to be a constraint.

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

### P2-4: Web playground (L)

`otsniff.example.com` — upload a PCAP, get a report. Real engineering:
hosting, file-size limits, rate limiting, cost management, abuse vectors,
TOS. Defer until and unless there's a demonstrated need.

### P2-5: Native packaging (S each, M total)

Homebrew formula, Debian/RPM packages, scoop manifest. Requires a stable
release cadence to be worth automating. **Deps:** P1-5 (a stable v0.2.0 to
package).

### P2-6: Ollama local provider (M)

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

### P2-7: Encrypted output bundle (S)

`otsniff bundle <report-stem> --passphrase` (or read passphrase from
env) — zips `report.html` + `map.json` + `audit.json` into one
file encrypted with a symmetric cipher. Inverse `unbundle` extracts
back.

**Why:** the BCSI handling commitment (NERC CIP-011 alignment) is
currently a documentation claim — we *say* the map file is sensitive
and should be protected at rest, and rely on the user to do so. A
first-party encrypted bundle moves that from "guidance" to "default
behavior." Doesn't change the privacy invariant — the AI still never
sees real values — but closes the at-rest exposure window between
`scrub` and `unscrub`. **Touches:** new `bundle` subcommand, new
dep on `age` or `cocoon` for the encryption primitive (`age` is the
modern choice; small footprint, audited).

### P2-8: User-defined rules via YAML (L)

`otsniff analyze --rules-file site.yml ...` loads additional
detectors from a user-provided YAML file. Schema is constrained:
a rule names an Observations field (e.g. `flows`, `cred_events`),
filter predicates, and a finding template. Not a full expression
language — closer to Sigma-rules-with-OT-specific-fields than to
generic rule engines.

**Why:** every plant has a few site-specific patterns the embedded
catalog will never cover ("any traffic to `192.168.10.0/24` outside
maintenance windows," "any `ENIP CIP write` to `controller-A` not
sourced from `eng-station-1`"). A constrained YAML format lets the
on-site engineer encode those patterns without forking the codebase.

**Why P2 / not P1:** Pandora's box. Once user rules exist, the
project owns a tiny detection-engine surface forever. Worth doing,
but only after the embedded catalog is rich enough that user rules
are a long-tail extension rather than a workaround. **Touches:** new
`rules/` module, YAML schema in `src/rules/schema.rs`, snapshot
tests on the deserializer. **Deps:** none functionally; conceptually
the catalog needs to be richer first.

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
- **Limited protocol coverage.** Modbus + EtherNet/IP + S7Comm + DNP3.
  Covers most US industrial plants and utilities by install base, but
  not building automation (BACnet) or modern OPC-UA-only deployments.
- **Capture-source classification can be inconclusive.** Pre-filtered
  captures often classify as "ambiguous" — we report this honestly rather
  than guess. The override flag (P0-5) is the workaround.
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
