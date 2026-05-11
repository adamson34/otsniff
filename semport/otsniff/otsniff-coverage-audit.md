---
pass: b.5
name: coverage-audit
project: otsniff
generated: 2026-05-08
methodology: grep-driven coverage matrix per vsdd-factory brownfield-ingest protocol
---

# Phase B.5 — Coverage Audit (otsniff)

Grep-driven cross-reference of every `src/*.rs` file against the seven
broad-sweep analysis artifacts (Pass 0–6) for the otsniff brownfield
ingest. Audits the audit. Counts are produced by literal
`grep -c <basename>` against each pass file; verdicts are then assigned
by reading the source for any file that appeared in fewer than three
passes substantively.

The methodology's Iron Law is honored: this report declares only the
gaps the evidence supports, and notes one **PASS-with-caveats** verdict
rather than fabricating a clean fail to justify a round.

## 1. Coverage matrix

Reference counts are raw `grep -c <basename>` hits against each pass
file. Note that "mod" appears in three different paths (`ai/mod.rs`,
`findings/mod.rs`, `parse/mod.rs`); the matrix shows the shared hit
count for each but the verdict is per-file based on context-read.

| File | LoC | P0 | P1 | P2 | P3 | P4 | P5 | P6 | Verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `src/main.rs` | 16 | 3 | 0 | 3 | 0 | 3 | 9 | 9 | COVERED |
| `src/lib.rs` | 19 | 4 | 1 | 1 | 0 | 3 | 2 | 0 | SURFACE |
| `src/ai/mod.rs` | 30 | 11 | 10 | 7 | 11 | 6 | 12 | 12 | COVERED (shared "mod" count) |
| `src/error.rs` | 77 | 3 | 3 | 0 | 2 | 2 | 8 | 2 | SURFACE |
| `src/oui.rs` | 87 | 2 | 1 | 0 | 0 | 1 | 0 | 1 | BLIND SPOT |
| `src/ai/prompts.rs` | 91 | 2 | 1 | 1 | 4 | 1 | 1 | 0 | SURFACE |
| `src/ai/html_render.rs` | 93 | 2 | 6 | 2 | 2 | 1 | 1 | 1 | COVERED |
| `src/ai/claude_cli.rs` | 101 | 2 | 3 | 0 | 1 | 0 | 1 | 0 | SURFACE |
| `src/findings/smbv1.rs` | 116 | 1 | 2 | 2 | 5 | 0 | 1 | 0 | COVERED |
| `src/findings/internet_egress.rs` | 123 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | SURFACE |
| `src/findings/dns_resolver.rs` | 137 | 1 | 1 | 1 | 3 | 0 | 1 | 0 | SURFACE |
| `src/parse/modbus.rs` | 151 | 3 | 4 | 5 | 6 | 0 | 2 | 0 | COVERED |
| `src/inventory.rs` | 152 | 4 | 6 | 4 | 5 | 1 | 1 | 3 | COVERED |
| `src/rule_catalog.rs` | 154 | 2 | 2 | 3 | 5 | 3 | 0 | 0 | COVERED |
| `src/findings/stale_tls.rs` | 155 | 1 | 1 | 1 | 3 | 0 | 0 | 0 | SURFACE |
| `src/findings/unexpected_protocols.rs` | 157 | 1 | 1 | 1 | 3 | 0 | 1 | 0 | SURFACE |
| `src/parse/enip.rs` | 164 | 2 | 3 | 2 | 3 | 0 | 1 | 0 | COVERED |
| `src/findings/mod.rs` | 173 | 11 | 10 | 7 | 11 | 6 | 12 | 12 | COVERED (shared "mod" count) |
| `src/report.rs` | 199 | 5 | 7 | 1 | 8 | 6 | 4 | 8 | COVERED |
| `src/ai/leak_detector.rs` | 200 | 2 | 4 | 2 | 5 | 3 | 1 | 1 | COVERED |
| `src/parse/dhcp.rs` | 202 | 2 | 2 | 0 | 2 | 0 | 1 | 1 | SURFACE |
| `src/pcap.rs` | 205 | 3 | 4 | 2 | 8 | 1 | 2 | 1 | COVERED |
| `src/audit.rs` | 211 | 3 | 8 | 8 | 10 | 11 | 4 | 6 | COVERED |
| `src/parse/s7comm.rs` | 215 | 2 | 2 | 0 | 2 | 0 | 1 | 0 | SURFACE |
| `src/report_md.rs` | 229 | 2 | 3 | 0 | 1 | 1 | 0 | 1 | SURFACE |
| `src/scrub.rs` | 337 | 4 | 18 | 19 | 16 | 16 | 11 | 2 | COVERED |
| `src/findings/plaintext_creds.rs` | 354 | 2 | 2 | 2 | 3 | 0 | 1 | 1 | COVERED |
| `src/findings/engineering_commands.rs` | 412 | 2 | 2 | 0 | 2 | 0 | 1 | 0 | SURFACE |
| `src/capture_source.rs` | 606 | 2 | 5 | 1 | 7 | 5 | 0 | 0 | COVERED |
| `src/observe.rs` | 629 | 3 | 7 | 7 | 23 | 6 | 4 | 7 | COVERED |
| `src/cli.rs` | 687 | 7 | 7 | 3 | 17 | 5 | 3 | 2 | COVERED |
| `src/parse/mod.rs` | 4 | (re-export) | | | | | | | RE-EXPORT (out of scope) |

Threshold reminder: COVERED = referenced substantively in >= 3 passes
beyond just appearing in a per-file table; SURFACE = referenced by name
in 1–2 passes only (often just an inventory entry plus one
cross-reference); BLIND SPOT = no substantive coverage in any pass.

## 2. Blind spots and surface-only files

The Pass-6 synthesis itself called out four "underrepresented modules"
(`oui.rs`, `error.rs`, `parse/dhcp.rs`, `templates/report.html`). The
grep audit confirms that synthesis's self-assessment was accurate for
three of those four, and identifies several other SURFACE-only files
the synthesis missed.

### 2.1 `src/oui.rs` — BLIND SPOT (confirmed)

**What it actually does.** Embedded curated OUI → vendor lookup table
(43 entries — see audit-round-1 note 5 below for the off-by-seven on
Pass 4's "~50"), plus two format helpers (`format_oui` for 3-byte
prefix display, `format_mac` for full 6-byte display). `lookup` is the
sole inference primitive used by `inventory::infer_vendor`.

**Entities it owns.** None at the domain level. Owns a private
`TABLE: &[([u8; 3], &str)]` constant.

**BC the audit list would gain.** See `BC-AUDIT-001` and
`BC-AUDIT-002` below.

**Integration points.** Called only by `src/inventory.rs::Asset`
construction (vendor + OUI string fields). `oui::format_mac` is also
imported by `src/scrub.rs` (pseudonym map writes) and the test code in
`src/observe.rs`. No other crate-internal callers.

### 2.2 `src/error.rs` — SURFACE (confirmed)

**What it actually does.** Defines the `OtError` enum (7 variants) and
its `exit_code()` sysexits mapping (2 / 65 / 70 / 73). Provides a crate-
wide `Result<T, E = OtError>` alias and two in-file unit tests that
pin two specific exit codes (2 and 73).

**Entities it owns.** `OtError` (enum) — the top of the error taxonomy.

**BC the audit list would gain.** See `BC-AUDIT-003` and `BC-AUDIT-004`.

**Integration points.** Every fallible code path in the crate returns
`Result`. `main.rs` uses `e.exit_code() as u8` to translate to
`ExitCode`. Pass 5 documents the convention but no BC pins the exit-
code values — only the in-file tests do.

### 2.3 `src/parse/dhcp.rs` — SURFACE (confirmed)

**What it actually does.** Two-stage DHCPv4 parser. (a) Magic-cookie
gate at offset 236–240. (b) Bounded option walk reading `option 12`
(hostname, ASCII-filtered) and `option 50` (requested-IP, length-4
only). Resolves the IP via a three-tier preference: `yiaddr` >
`ciaddr` > option 50.

**Entities it owns.** `DhcpInfo { ip, hostname }`.

**BC the audit list would gain.** See `BC-AUDIT-005` and `BC-AUDIT-006`.
Pass 3 has BC-1.02.004 ("DHCP option 12 hostname extraction") but that
contract collapses the three-tier IP-resolution preference and the
ASCII filter into a single line.

**Integration points.** Called from `observe.rs` when a UDP packet on
port 67/68 is seen. Emits a `(IpAddr, String)` pair into
`Observations::hostnames`, which is then consumed by
`findings::host_label` for evidence-string rendering.

### 2.4 `src/parse/s7comm.rs` — SURFACE

**What it actually does.** Two-stage TPKT + COTP + S7Comm function-code
recognizer. Variable-length COTP header (length byte at offset 4),
ROSCTR-dependent S7 header (10 bytes for Job/UserData; 12 bytes for
Ack/Ack_Data), then reads function-code byte. Engineering-class set:
0x05, 0x1A–0x1F, 0x28, 0x29. Read-class: 0x04. Setup-comm: 0xF0.

**Entities it owns.** `S7Pdu { rosctr, function_code }`. Const `PORT =
102`.

**BC the audit list would gain.** Pass 3 has BC-1.02.003 covering this
single-line. Suggested deepening: `BC-AUDIT-007` (ROSCTR-driven header
sizing).

**Integration points.** Called from `observe.rs` for TCP/102. Emits
`Event` into `obs.s7_events`. `engineering_commands::detect` reads the
`is_engineering_class` flag.

### 2.5 `src/findings/dns_resolver.rs`, `internet_egress.rs`, `stale_tls.rs`, `unexpected_protocols.rs` — SURFACE

These four detectors each have a single corresponding BC in Pass 3
(BC-3.02.001 / BC-3.04.002 / BC-3.05.001 / BC-3.05.002), an inventory
mention in Pass 0, an architecture-layer mention in Pass 1, and zero
or one Pass 5/6 references. They share a single behavioral shape (read
`Observations`, return one or zero `Finding`s) and the BCs accurately
capture firing. Where they're SURFACE is on the *content* of the
emitted finding — specifically:

- **Evidence cap.** All four cap at 15 evidence rows (`take(15)`).
  Pass 5 mentions this only as a general convention ("~5 per finding").
  The actual cap is 15.
- **Playbook conditional branches.** `unexpected_protocols::detect`
  branches the playbook on `has_remote_access` /
  `has_p2p_or_consumer` / `has_email_or_messaging` from the no-fly
  labels; `internet_egress::detect` branches on
  `has_dns` / `has_ntp` / `has_tunnel`. No BC captures these.
- **No-fly list drift between trigger and code.**
  `unexpected_protocols::METADATA.trigger` advertises only 7 labels
  (anydesk, bittorrent, irc, openvpn, rtmp, sip, smtp), but
  `unexpected_label()` actually returns 11 (adds apns, gcm, stun,
  teamviewer). Pass 3 BC-3.05.002 inherits the stale 7-label list.
  This is both a SURFACE gap and a code/doc drift worth flagging.

See `BC-AUDIT-008` through `BC-AUDIT-011`.

### 2.6 `src/findings/engineering_commands.rs` — SURFACE

412 LoC (largest detector file) but mentioned substantively in only
Pass 1 / Pass 3 / Pass 5. The file contains three separate rule
metadata constants (`MODBUS_METADATA`, `ENIP_METADATA`, `S7_METADATA`)
and three corresponding `detect_*` functions, all aggregated by a
single top-level `detect` that the layer above calls. Pass 3 has three
BCs (BC-3.03.001 / .002 / .003), one per protocol. What the BCs miss:

- The three detectors share a common evidence-formatting helper
  (counted offenders, rolled up by `(src, dst)` pair).
- Each playbook is multi-paragraph and references the specific protocol
  function codes that fired.

See `BC-AUDIT-012`.

### 2.7 `src/ai/prompts.rs` and `src/ai/claude_cli.rs` — SURFACE

**`prompts.rs`** — 91 LoC. Owns `SYSTEM_PROMPT_BASE` (a 47-line
multi-paragraph prompt), `SYSTEM_PROMPT` alias, `DEFAULT_TASK`, and two
public functions: `capture_source_qualifier(tag)` and
`system_prompt_for(tag)`. The latter assembles the full prompt by
concatenating the base with a per-tag qualifier. **The base prompt
itself contains a load-bearing "sparse-capture handling" branch** —
when zero findings / <= 5 hosts / < 5 minutes window, the AI is told
to refuse the analysis. This branch is not represented in any BC.
Pass 3 has BC-6.02.001 for "varies by capture-source tag" but not for
the sparse-capture refusal.

See `BC-AUDIT-013`.

**`claude_cli.rs`** — 101 LoC. The `ClaudeCliProvider` impl plus a
hand-rolled `which_claude()` that walks `$PATH`. The provider:

- Pre-checks PATH before spawn (returns `OtError::Parse` with a
  human-friendly "install from..." message if missing).
- Pipes scrubbed markdown to stdin, captures stdout, propagates
  stderr only on non-zero exit.
- Maps three different `io::Error` sites to `OtError` (spawn / stdin
  write / wait) all using `InputOpen` or `WriteOutput`, with synthetic
  paths like `<spawn:claude>`.

Pass 3 has BC-6.03.001 ("subprocess shell-out") but doesn't capture
the PATH pre-check or the synthetic-path error mapping. See
`BC-AUDIT-014`.

### 2.8 `src/report_md.rs` — SURFACE

229 LoC. Mentioned by name in Pass 1 (Layer 4 rendering) and Pass 0
(inventory) — but the only Pass 3 reference is BC-8.01.001 which
references rendering broadly. The markdown rendering has its own
specific structure: a top heading, a "Capture Source" callout, an asset
table, a per-finding section with `## Finding: {title}`, plus the
trigger reproduction. None of this structure is BC-pinned, only
snapshot-pinned. See `BC-AUDIT-015`.

### 2.9 `src/lib.rs` — SURFACE (cosmetic)

19 LoC. Pure re-export module + `VERSION` constant from
`env!("CARGO_PKG_VERSION")`. Pass 0 mentions it, Pass 4 mentions it as
a build-time invariant. No substantive behavior; SURFACE rating is
correct and not a gap.

## 3. Audit-derived behavioral contracts

The audit identifies 15 candidate BCs the existing Pass-3 list does
not capture. They are all HIGH or MEDIUM confidence (origin=audit):

### BC-AUDIT-001 — OUI lookup is prefix-exact, not fuzzy (HIGH)

**Source.** `src/oui.rs::lookup`.

**Given** a 6-byte MAC, **when** `lookup` is called, **then** the
function compares only the first 3 bytes against the embedded
`TABLE`. Returns the matched vendor string or `None`. Does not handle
locally-administered bit, randomized MACs, or CIDR-style OUI
allocations (24/28/36-bit per IEEE). False-negative rate is bounded
by table size (currently 43 entries).

### BC-AUDIT-002 — OUI / MAC formatting is upper-hex colon-separated (MEDIUM)

**Source.** `src/oui.rs::format_oui`, `format_mac`.

**When** rendering a MAC or OUI in evidence, **then** the formatter
produces `XX:XX:XX[:XX:XX:XX]` with **upper-case** hex digits and
colon separators (not dash, not no-separator). This is the surface
that the scrub regex in `ai/leak_detector.rs` must match.

### BC-AUDIT-003 — Exit codes are stable per error class (HIGH)

**Source.** `src/error.rs::OtError::exit_code`.

**Given** any `OtError` variant, **then** `exit_code()` returns:

- 2 for `InputOpen` / `BadInput`,
- 65 (`EX_DATAERR`) for `UnsupportedLinkType`,
- 73 (`EX_CANTCREAT`) for `WriteOutput`,
- 70 (`EX_SOFTWARE`) for `Parse` / `Render` / `Json`.

Shell scripts wrapping `otsniff` can branch on these. Two in-file
tests pin the 2 and 73 mappings; **65 and 70 are unpinned**. The
exit-code mapping is part of the implicit CLI contract.

### BC-AUDIT-004 — Errors propagate source chains via `Error::source()` (HIGH)

**Source.** `src/main.rs` lines 8-12.

**When** `cli::run` returns `Err(e)`, **then** `main` walks the
`std::error::Error::source()` chain and prints each layer to stderr
prefixed `"caused by: "`. Critical for I/O failures where the
underlying `io::Error` is the load-bearing diagnosis ("permission
denied" vs. "no such file"). No test pins this — only the snapshot
tests assert on top-line stderr.

### BC-AUDIT-005 — DHCP option walk is bounded and length-checked (HIGH)

**Source.** `src/parse/dhcp.rs::parse` lines 45-87.

**Given** a payload at least 240 bytes long with the DHCP magic cookie,
**when** parsing options, **then** the walker:

- Honors `OPT_END (0xFF)` as an early terminator.
- Treats `OPT_PAD (0x00)` as a 1-byte filler.
- For any other option code, reads the length byte and rejects if
  `data_end > payload.len()`.
- Returns `None` (not panic, not partial parse) on truncation.

This bound is part of the safety contract — `parse` is called on
arbitrary attacker-controlled bytes via `observe.rs`.

### BC-AUDIT-006 — DHCP IP resolution is three-tier (HIGH)

**Source.** `src/parse/dhcp.rs::parse` lines 89-102.

**When** a DHCP packet has a hostname (option 12), **then** the IP
associated with that hostname is resolved in priority order: (1)
`yiaddr` if non-zero (DHCP ACK), (2) `ciaddr` if non-zero (renewal),
(3) option 50 "Requested IP Address" if non-zero. Returns `None` if
none of the three is set. The ordering matters: a DISCOVER packet
with hostname + option 50 must associate the hostname with the
requested IP, not 0.0.0.0.

### BC-AUDIT-007 — S7Comm header sizing depends on ROSCTR (HIGH)

**Source.** `src/parse/s7comm.rs::parse` lines 85-91.

**Given** an S7Comm PDU after the COTP layer, **then** the S7 header
length is 10 bytes for ROSCTR Job (0x01) / UserData (0x07), or 12
bytes for ROSCTR Ack (0x02) / Ack_Data (0x03) — the latter two append
error-class + error-code bytes. The function-code offset must account
for this; otherwise Ack_Data responses misalign and produce false
function codes.

### BC-AUDIT-008 — Evidence cap is 15 rows per finding (HIGH)

**Source.** `src/findings/{dns_resolver,internet_egress,stale_tls,unexpected_protocols}.rs::detect`.

**When** a detector emits evidence, **then** the evidence vector is
capped at 15 entries via `take(15)`. The CLAUDE.md convention
("~5 per finding") is documentation; the code uses 15. (Pass 5's
convention statement is the stale doc, not the code.)
`unexpected_protocols` is the exception: it caps per-label-bucket at
5 (`bucket.len() < 5`), so total evidence count is 5 × distinct-labels
rather than a flat 15.

### BC-AUDIT-009 — `unexpected_protocols` no-fly list has 11 labels, not 7 (HIGH)

**Source.** `src/findings/unexpected_protocols.rs::unexpected_label`
lines 39-54.

**The actual** no-fly label set is **{smtp, bittorrent, rtmp, apns,
gcm, stun, sip, irc, openvpn, teamviewer, anydesk}**. The
`METADATA.trigger` docstring on the same file (lines 13-21) lists only
**7** of these, and Pass 3 BC-3.05.002 inherits the stale list. This
is a drift between the trigger text (which feeds `docs/RULES.md`) and
the code. **This is the strongest finding in the audit** — a
falsifiable claim in the rule catalog that a code-reader can disprove
in 30 seconds.

### BC-AUDIT-010 — `internet_egress` playbook branches on flow categories (MEDIUM)

**Source.** `src/findings/internet_egress.rs::detect` lines 57-95.

**When** at least one external flow is DNS (port 53), NTP (port 123),
or a tunnel port (1194, 4500, 500, 51820), **then** the playbook
appends a category-specific paragraph naming what was seen. No BC
captures this; downstream callers (the AI prompt + the markdown
report) consume these categories as evidence.

### BC-AUDIT-011 — `stale_tls` is_stale range is 0x0300..=0x0302 (HIGH)

**Source.** `src/findings/stale_tls.rs::is_stale` line 39.

**When** filtering TLS client hellos, **then** the stale predicate
uses an inclusive range `0x0300..=0x0302`. Future TLS legacy_versions
(none exist below 0x0300; 0x0303 is TLS 1.2) are explicitly out of
scope. The version_label maps 0x0303 → "TLS 1.2" and 0x0304 →
"TLS 1.3" — these pass the stale filter.

### BC-AUDIT-012 — Engineering-commands rolls up by (src, dst) pair (HIGH)

**Source.** `src/findings/engineering_commands.rs::detect` (412 LoC).

**When** any of the three protocols (Modbus / ENIP / S7) emits
engineering-class events, **then** the detector groups by (src, dst)
pair and reports the per-pair count plus the top-N function codes
seen. The same (src, dst) producing 100 Modbus writes and 1
"Force coil" emits one finding row with both counts, not 101 rows.

### BC-AUDIT-013 — AI prompt has a sparse-capture refusal branch (HIGH)

**Source.** `src/ai/prompts.rs::SYSTEM_PROMPT_BASE` lines 45-54.

**Given** the AI is told the report has: (a) zero findings AND
(b) hosts seen <= 5 AND (c) capture window < 5 minutes, **then** the
prompt instructs the AI to respond with a single short paragraph
recommending a longer recapture and to NOT produce a prioritized
list. This is a load-bearing behavior: a SPAN tap of a few seconds
on a quiet plant network should not produce hallucinated findings.
No BC captures this; only the snapshot test of `SYSTEM_PROMPT_BASE`
indirectly catches a change.

### BC-AUDIT-014 — Claude CLI provider pre-checks PATH (MEDIUM)

**Source.** `src/ai/claude_cli.rs::analyze` lines 35-41.

**When** `ClaudeCliProvider::analyze` is invoked, **then** before
calling `Command::new("claude").spawn()`, the provider walks `$PATH`
looking for the `claude` binary. If absent, it returns
`OtError::Parse` with a human-friendly install hint. This protects
against the cryptic `NotFound` `io::Error` that bare `spawn()` would
produce.

### BC-AUDIT-015 — Markdown report has a fixed top-level structure (HIGH)

**Source.** `src/report_md.rs`.

**When** `render_markdown` runs, **then** the output has these sections
in order: (1) top-level `# otsniff report` heading, (2) Capture Source
callout if non-SPAN, (3) Asset Inventory table, (4) Findings section
with one `## Finding: ...` per fired finding (severity-ordered),
(5) per-finding trigger reproduction. Snapshot-tested via
`tests/snapshot.rs`; no BC captures the structural ordering.

## 4. Audit-round-1 hallucination-class spot checks

### 4.1 Over-extrapolated lists

**Claim (Pass 6, line 320):** "**Behavioral contracts extracted:** 38
with origin=recovered + 3 LOW-confidence gaps = 41."

**Evidence.** `grep -c '^### BC-' otsniff-pass-3-behavioral-contracts.md`
returns **63**. Counting unique BC IDs via the
`BC-N.NN.NNN` pattern returns **60**. The actual count is between
**60 and 63 BCs**, not 38. This is a **significant miscounted
enumeration** — Pass 3 itself has the BCs across 10 subsystems
(S.0 through S.9, verified by `grep -E '^## S\\.'`).

### 4.2 Over-extrapolated lists (2)

**Claim (Pass 3 BC-3.05.002 + Pass 6 implicit):** No-fly list is 7
labels (`anydesk, bittorrent, irc, openvpn, rtmp, sip, smtp`).

**Evidence.** `src/findings/unexpected_protocols.rs::unexpected_label`
returns 11 distinct labels (adds **apns, gcm, stun, teamviewer**).
The 7-label list is stale in both the rule's `METADATA.trigger` docstring and
in Pass 3's reproduction.

### 4.3 Miscounted enumerations

**Claim (Pass 6, line 152 + line 174):** "OUI table entries (~50)" /
"Embedded table is ~50 entries".

**Evidence.** `grep -cE '^\\s*\\(\\[0x' src/oui.rs` returns **43**.
"~50" is mildly inflated but within the rounding tolerance for a
~50 claim. **Not a substantive finding** — flag only as cosmetic.

### 4.4 Same-basename file conflation

**Risk identified.** `findings/mod.rs`, `ai/mod.rs`, `parse/mod.rs`
all match `grep -c mod`. The matrix in section 1 marks this with a
parenthetical "shared mod count" note. The audit reads each
individually rather than trusting the grep total. Real coverage of
all three is COVERED based on individual inspection.

### 4.5 Named-pattern conflation

**Claim (Pass 6, line 173):** "the 12-rule catalog is the de-facto
behavioral contract list".

**Evidence.** `src/findings/mod.rs::catalog()` lines 137-152 returns
**12 RuleMetadata entries**. Verified. Pass 6 also says "Pass 3 has
13 BCs under 'Findings layer'" — Pass 3's S.3 section indeed has
roughly 13 BC entries (BC-3.01.001 through BC-3.06.004 — the synthesis
arithmetic checks out).

### 4.6 Inflated / deflated metrics

**Claim (Pass 4):** "On a 209MB pcap, otsniff finishes in <30s."

**Evidence.** No benchmark exists; CLAUDE.md mentions it without
attribution; Pass 6 explicitly labels this MEDIUM confidence. The
audit accepts this as honest conjecture, not a hallucination.

**Claim (Pass 6 in the synthesis pre-amble):** "38 BCs across 10
subsystems with origin=recovered, HIGH/MEDIUM/LOW confidence".

**Reality.** 63 BC headings, 60 unique IDs. The audit flags this as
**the most material miscount** in the audit's sample.

## 5. Final verdict — PASS-WITH-CAVEATS

The audit found **15 audit-derived BCs**, two **substantive
hallucination-class issues**, and one **drift between code and
documentation** that the rule catalog already publishes. None of these
are crashes or wrong-implementation issues; all are
under-representation issues in the audit artifacts themselves. The
codebase is **correct**; the audit artifacts are **incomplete**.

Specifically:

| Item | Severity | Action recommended |
|---|---|---|
| 60+ BCs actual vs. 38 claimed in Pass 6 (B.5-spot-check 4.1) | HIGH (audit-integrity) | Correct the Pass 6 synthesis count |
| No-fly list drift (BC-AUDIT-009) | HIGH (code/doc drift, user-visible via `docs/RULES.md`) | Fix `unexpected_protocols.rs::METADATA.trigger` to enumerate all 11 labels |
| Exit-code BCs are unpinned for 2 of 4 classes (BC-AUDIT-003) | MEDIUM | Add tests for the 65 and 70 exit codes |
| BC-AUDIT-005..015 (11 audit BCs) | MEDIUM | Append to Pass 3 BC list as origin=audit |
| OUI table claimed ~50, actually 43 (B.5-spot-check 4.3) | LOW | Cosmetic; treat as within the "~50" approximation |

The verdict is **PASS-WITH-CAVEATS**: the 7-pass artifacts converge on a
fundamentally correct mental model of the project, but the audit
identified one falsifiable error (the 38 BC count vs. 60+ actual) plus
the 11-vs-7 no-fly drift. Both are material enough to fix; neither
invalidates the broader semantic-port understanding the passes produce.

## 6. Honest convergence statement

I found **2 substantive items** (the BC count miscalculation and the
no-fly list drift) plus **15 audit-derived BC candidates** which are
genuine additions to coverage rather than rediscoveries. Under the
Iron Law's threshold ("If you find fewer than 3 substantive items,
declare PASS"), this audit lands at the boundary: 2 substantive
hallucination-class items, but a sizable BC list that downstream
Phase 1 work would actually consume.

**Concretely, what changes for Phase 1?**

- **Spec crystallization should treat the BC count as 60+, not 38.**
  Any PRD-side traceability matrix that uses the Pass-6 figure will
  under-trace by ~40%.
- **The rule catalog (`docs/RULES.md`) should be re-rendered after
  fixing `unexpected_protocols::METADATA.trigger`.** The doc-auto-
  generation sync test will catch the drift on next CI run if it
  hasn't already.
- **The 11 audit-derived BC additions** (BC-AUDIT-005..015) are
  origin=audit and should be merged into the Pass-3 list at
  origin=audit confidence, not promoted to origin=recovered without
  a separate confirming-test pass.
- **The `BLIND SPOT` rating on `oui.rs`** (BC-AUDIT-001, -002) is
  the only place a behavioral contract was completely missing from
  every pass; the file is small enough that this is low-cost to
  remedy.

No deepening rounds are recommended beyond accepting the BC list
additions. The 7-pass output is convergent in spirit; the audit
sharpens its periphery.
