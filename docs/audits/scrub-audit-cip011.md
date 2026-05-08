# Scrub audit — NERC CIP-011 / IEC 62443 alignment

_Date: 2026-05-08. Scope: all extraction and rendering paths in otsniff
as of develop @ `c00904e`._

## Why this audit exists

The scrub layer is the project's load-bearing privacy claim. Every
feature that extracts new data or renders new fields is a potential
leak vector. Doing this audit *now* — and turning it into a repeatable
process for new features (see `docs/specs/scrub-stance-template.md`)
— is what lets us say "designed to align with BCSI handling" honestly.
Without it, the AI feature accumulates leak vectors as the extractor
and finding layers grow.

This is not a regulatory certification. It is a documented engineering
review against published BCSI categories so that a customer's compliance
team has a concrete artifact to evaluate against their own risk register.

## Frameworks referenced

- **NERC CIP-011** (BES Cyber System Information). Applies to power-
  sector entities subject to FERC. Defines BCSI as "information about
  the BES Cyber System that could be used to gain unauthorized access
  or pose a security threat" — explicitly including identifiers,
  network topology, and operating procedures.
- **IEC 62443-3-3** (System security requirements). Sections SR-1.x
  (identification & authentication) and SR-5.x (restricted data flow)
  are the analogues; "industrial control system information" carries
  similar handling expectations across sectors.
- **TSA pipeline security directive** (US, 2021+). Treats network
  diagrams and asset identifiers as restricted.
- **NIS2** (EU). Mostly aligned with the above for OT networks.

The categories below are written against CIP-011 because it's the
clearest. The scrub stance applies regardless of which framework the
operator's compliance team uses.

## BCSI classification used in this audit

| Class       | Examples                                                 | Default scrub stance |
|-------------|----------------------------------------------------------|----------------------|
| **High**    | Hostnames identifying critical assets, usernames, serial numbers, firmware/model strings, device tag names from process payloads, named project / station names | **Must** be pseudonymized |
| **Medium**  | IP addresses, MAC addresses, network topology shape (which host talks to which), exact timestamps | **Must** be pseudonymized (IPs/MACs); shape preserved |
| **Low**     | Vendor names ("Siemens", "Schneider"), inferred role labels, protocol names, function-code labels, severity labels, aggregate counts | Preserved |
| **Internal**| Raw payload bytes, decoded protocol fields not surfaced in any output | Must not be rendered (kept in-memory only or `#[serde(skip)]`) |

## Field-by-field audit

### Observations layer (`src/observe.rs`)

Every field in the `Observations` struct, classified.

| Field | Source | Current scrub stance | BCSI class | Notes |
|---|---|---|---|---|
| `hosts.ip` | Ethernet/IP header | Scrubbed → `host_NNN` | Medium | ✅ Covered |
| `hosts.macs[]` | Ethernet header | Scrubbed → `mac_NNN` | Medium | ✅ Covered |
| `hosts.protocols` | Heuristic from port + payload | Preserved | Low | ✅ Vendor-agnostic protocol names |
| `hosts.first_seen` / `last_seen` | Packet timestamp | Preserved | Medium | Timing patterns *can* fingerprint operations. Acceptable for triage; documented trade-off. |
| `hosts.packets` / `bytes` | Counters | Preserved | Low | Aggregates, not identifiers |
| `hosts.in_ot_zone` | Computed from `--ot-subnet` flag | Preserved | Low | Boolean classification |
| `flows.key.src` / `dst` | Packet header | Scrubbed (via map) | Medium | ✅ Covered |
| `flows.key.dst_port` | Packet header | Preserved | Low | Standard service ports — not BCSI |
| `flows.label` | Heuristic from port | Preserved | Low | Protocol names |
| `flows.unique_src_ports` | Packet header | Preserved as count | Low | Connection count, not the ports |
| `modbus_events.{src,dst}` | Packet header | Scrubbed | Medium | ✅ |
| `modbus_events.function_code` / `label` | Modbus PDU | Preserved | Low | Standard FC labels — "Write Single Coil" etc. |
| `enip_events.*` | ENIP/CIP fields | Same shape as modbus_events | Low/Medium | ✅ FC-level only; we don't decode CIP item names today |
| `s7_events.*` | S7Comm fields | Same | Low/Medium | ✅ FC-level only; we don't decode S7 DB names today |
| `cred_events.{src,dst,dst_port}` | Header | Scrubbed | Medium | ✅ |
| `cred_events.kind` | Enum | Preserved | Low | Enum, not a name |
| **`cred_events.note`** | **Payload bytes** | **In-memory only; not rendered** | **High** | ⚠️ **Gap:** see Finding #1 below |
| `external_flows.*` | Header | Scrubbed | Medium | ✅ |
| `smbv1_packets` keys | Header | Scrubbed | Medium | ✅ |
| `tls_client_hellos` keys | Header | Scrubbed | Medium | ✅ |
| `hostnames.*` | DHCP option 12 | Scrubbed → `name_NNN` | High | ✅ Covered (P0-3) |
| `mac_frame_counts` | Header | In-memory only; aggregates surface in capture-source line | Medium | The dominant MAC *value* leaks via `Classification::HostSide.dominant_mac` — but that path goes through `scrub_text` (verified by `classification_report_line_does_not_leak_unscrubbed_values_via_pseudonym_path`) ✅ |
| `broadcast_frames` | Counter | Preserved | Low | Aggregate |

### Rendering layer

| Output | Surface | Scrub status |
|---|---|---|
| HTML (`render_html`) | Inventory + findings + top flows | All identifiers run through `AssetView` / `FindingView` / `TopFlow`, all of which carry only fields whitelisted as scrubbable |
| Markdown (`render_markdown`) | Same shape | Same |
| JSON output (`--json`) | `inventory` + `findings` only — **not** raw `Observations` | Scope-limited by design |
| Scrub map JSON (`--map`) | The map itself | Real values are inside the map; the file is the user's secret to manage (same threat model as the original PCAP) — see ADR-0006 |
| Markdown via `analyze` (AI-bound) | Goes through `scrub_text` + `ensure_clean` + `ensure_no_map_values` before any provider call | ✅ Dual leak detector (P0-3) |

### AI-bound assets (`src/ai/prompts.rs`)

| Field | Status |
|---|---|
| `SYSTEM_PROMPT` | Snapshot-tested; checked by `prompts_contain_no_real_identifiers` |
| `DEFAULT_TASK` | Same |
| Per-source qualifier prompts | Same |
| Capture-source classification line | Goes through `scrub_text` before prompt assembly |

## Findings

### Finding #1 — `CredEvent.note` is High-BCSI but is reachable via `Serialize`

**What.** `CredEvent.note` holds extracted payload bytes:

- For `FtpAuth`: the literal `USER ENGINEER1` or `PASS hunter2` line
  (capped at 80 bytes by `first_line`).
- For `HttpBasic`: the literal `Authorization: Basic <b64>` header,
  where the base64 is trivially decodable to `username:password`.
- For `TelnetSession`: a generic constant string. Safe.
- For `Snmpv1v2c`: a generic constant string. Safe.

The first two carry **High BCSI** content (operational account names,
plaintext passwords). Today the field is not rendered in HTML, markdown,
or the `--json` output, so there is no leak in shipping output. But:

- `CredEvent` derives `Serialize`. Future code that adds `obs` or
  `cred_events` to a JSON payload would silently leak this.
- A future detector could include `note` in finding evidence to give
  an analyst more context — exactly the kind of "useful detail"
  request that erodes the privacy invariant.

**Severity.** Process gap, not a current leak. Equivalent to "loaded gun
in a drawer" — the safety is the discipline of not adding the wrong
output, not the type system.

**Fix.** Two changes:

1. Mark `CredEvent.note` `#[serde(skip)]` so it cannot reach any JSON
   output even if a future feature accidentally serializes the
   observations struct.
2. Add a sentinel test that injects a known username into a synthetic
   `CredEvent.note` and asserts it does **not** appear in the rendered
   markdown or HTML. This is what catches the regression where a
   future detector starts including `note` in evidence.

If a future feature wants to surface usernames intentionally, it must:
- declare a new `user_NNN` pseudonym class in `ScrubMap`,
- extract usernames at observation time into a typed field (not the
  raw byte slice),
- update the leak detector and the snapshot fixture.

This is exactly the kind of "declare your scrub stance" decision the
template (next section) requires.

### Finding #2 — Network topology shape leaks even with all identifiers scrubbed

**What.** The top-flows table preserves the *shape* of communications:
which logical host talks to which on which port. Pseudonymizing the
endpoints to `host_NNN` doesn't hide the comms matrix — and the comms
matrix is itself operational metadata. An adversary who knows the
target plant's vendor mix could correlate the matrix shape (e.g., "5
PLCs cyclically polled by 1 HMI on 502") with public information about
specific deployments.

**Severity.** Acceptable trade-off. The AI cannot reason usefully without
the comms shape; a sanitized matrix that hides the structure removes
the entire value of AI-assisted triage. CIP-011 contemplates this kind
of trade-off for legitimate operational use.

**Fix.** No code change. Documented in this audit so the trade-off is
explicit, and re-evaluated if customer requirements push us toward
heavier sanitization (e.g., shape-only summaries for high-classification
sites). The user always retains the option not to invoke `analyze` at
all and use `report` only locally.

### Finding #3 — Vendor names are preserved; this is not a leak

**What.** OUI lookup translates a MAC OUI to "Siemens", "Rockwell", etc.
That string is preserved in the scrubbed report.

**Severity.** Low. "Siemens" by itself doesn't fingerprint a specific
operator. Vendor inference is also derivable from the OUI directly,
which any analyst with the IEEE registry could do — we're not
revealing anything secret. Preserving vendor labels measurably
improves the AI's reasoning quality (specific advice for Siemens
vs. Allen-Bradley environments).

**Fix.** None. Documented.

### Finding #4 — Timestamps are preserved

**What.** First-seen / last-seen timestamps and the capture window
appear in the rendered output. Operational schedules can sometimes be
inferred ("plant was active during night shift").

**Severity.** Low-to-Medium. Acceptable for triage; if a customer's
risk model rejects this, they can post-process the report to coarsen
timestamps. We do not currently coarsen because relative ordering is
diagnostically useful.

**Fix.** None today. A future `--coarsen-timestamps` flag could opt in
to hour-level rounding for sites with stricter posture. Not on the
roadmap.

## Process going forward

Every new feature spec under `docs/specs/` must include a "Scrub
stance" section that answers the four questions in
`docs/specs/scrub-stance-template.md`. PRs that add extractors or
rendered fields without filling in this section will be requested to
do so.

The audit will be re-run when:

- A new `*_event` type is added to `Observations`
- A new pseudonym class is added (`user_NNN`, `serial_NNN`,
  `model_NNN`, etc.)
- A new output surface is added (e.g., a SARIF exporter, CSV
  export, etc.)
- A regulatory framework explicitly listed above is updated

## Out of scope for this audit

- **Editable / customer-supplied scrub maps** (a customer wanting to
  override pseudonyms with their own labels) — separate feature.
- **Encryption of the scrub map at rest** — the user is responsible
  for protecting the map file under the same threat model as the
  original PCAP (ADR-0006). Adding age/gpg integration is a separate
  feature.
- **Differential privacy** for aggregate counts — not a goal; we want
  the analyst to see the actual counts.
- **Audit-grade certification** against any framework. We design for
  alignment, not certification — see `docs/ROADMAP.md` "Out of
  scope" for the longer reasoning.
