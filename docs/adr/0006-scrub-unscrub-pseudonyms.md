# ADR-0006: Scrub / unscrub for AI-assisted triage

## Status
Accepted (v0.2). Amended in v0.3 to add the hostname pseudonym class
and the NERC CIP-011 framing — see "Identifier classes and the NERC
CIP-011 framing" below.

## Context
Asset owners want AI assistance with PCAP triage but can't legally send
raw plant captures to an external LLM API. Plant networks routinely have
data classifications (regulated industries, vendor NDAs, plant operational
secrets fingerprintable from MAC OUIs and protocol patterns) that prohibit
that. Existing AI features in the OT space (Dragos, Nozomi, Claroty) only
work on the vendor's own cloud — there's no open path to "ask Claude to
look at this PCAP" that respects a CIO's risk register.

Result: small utilities and manufacturers — the audience this tool is for —
get no AI-assisted triage at all.

## Decision
Add a scrub/unscrub layer that produces an LLM-safe markdown report plus
a local pseudonym map. The user pastes the report into any LLM, gets a
response that references pseudonyms, and runs `unscrub` to map pseudonyms
back to real values for follow-up.

We do **not** ship an embedded AI client. The user picks their LLM
(Claude, GPT-4, local model, anything) and copies text by hand. This
keeps scope tight and respects the user's choice of vendor / privacy
posture / billing.

## What we scrub vs. preserve

**Scrubbed (every observation gets a pseudonym):**
- IPv4 / IPv6 addresses → `host_001`, `host_002`, ...
- MAC addresses → `mac_001`, `mac_002`, ...
- Hostnames (DHCP option 12 today; mDNS / NetBIOS planned) →
  `name_001`, `name_002`, ...

**Preserved (passes through unchanged):**
- Vendor names (`Siemens`, `Schneider Electric`, `Schweitzer Engineering`)
- Inferred role (`PLC`, `HMI`, `Engineering workstation`)
- Protocol names (`modbus`, `enip`, `dnp3`)
- Function-code labels (`Write Single Coil`, `Force Listen Only Mode`)
- Severity labels, packet/byte counts, timestamps
- General topology relationships (in_ot_zone boolean, comms-matrix shape)

Vendor and role labels are intentionally preserved because they're the
context an AI needs to reason usefully ("a Siemens PLC is doing X" is far
more useful than "host_001 is doing X"). They're also low-sensitivity —
seeing "Siemens PLC" in a chat doesn't fingerprint a specific plant.

## Pseudonym format

`<class>_<index>` where class ∈ `{host, mac, name}` and index is
decimal, zero-padded to 3 digits. The format is regex-safe:
`\b(?:host|mac|name)_[0-9a-f]+\b`. New identifier classes (e.g.,
`unit_NN` for Modbus unit IDs) extend the prefix vocabulary, not the
format.

Pseudonym assignment is **deterministic** — sorted by real value at map
build time. The same PCAP always produces the same map, so re-runs and
test snapshots are stable.

## Two-pass implementation

`build_map(&obs)` mints pseudonyms from observations only. Then the
markdown report is rendered with **real** values, and `scrub_text(rendered, &map)`
substitutes real → pseudonym **only for values present in the map**. This
constraint is load-bearing: an IP-shaped substring inside an unrelated
identifier (e.g., a serial number with dots) is never rewritten by accident,
because we only replace what we observed.

Trade-off: an IP that appears in the report but wasn't in observations
(currently impossible, but a future bug could introduce one) would leak.
The check `out.contains(real.as_str())` in `scrub_text` minimizes the
work but doesn't enforce a leak guarantee — that's enforced by the
discipline of not concatenating IPs into report text outside the data
model.

## Unscrub

`unscrub_text(text, &map)` regex-matches every pseudonym-shaped token in
the input, looks each up in the map. Hits get replaced with the real
value; misses (LLM-hallucinated identifiers, output from a different
scrub session, etc.) are reported and left as-is by default. `--strict`
mode treats any miss as an error — useful when the user has confidence
the LLM didn't make anything up.

## Rejected alternatives

- **Encrypt the map** — useful eventually, but wrong scope for v0.2.
  Today the map is a plain JSON file the user is responsible for
  protecting (same threat model as the original PCAP). Adding age/gpg
  integration is a separate feature.
- **Render once, scrub at the data layer** — would require typing IPs as
  `enum { Real(IpAddr), Pseudonym(String) }` throughout the data model.
  Big refactor, no functional benefit over post-render substitution.
- **Embed an LLM client** — couples otsniff to a vendor's API surface
  (and billing). The user picks the LLM; we just produce text.
- **Structured AI output (JSON contract)** — would force the user into a
  specific prompt template. Free-text round-trip works with any LLM and
  any prompt; structured output is a v0.3 hardening if/when we see
  enough usage to justify it.

## Audit and process

The systematic audit of the currently-shipped extraction and rendering
surface against NERC CIP-011 / IEC 62443 lives at
`docs/audits/scrub-audit-cip011.md`. Every new feature spec must
declare its scrub stance using the template at
`docs/specs/scrub-stance-template.md` — answering: what does it
extract, what does it render, what's the BCSI classification, what's
the scrub stance. PRs that add extractors or rendered fields without
that section will be requested to add it.

The audit is re-run when a new event type is added to `Observations`,
when a new pseudonym class is added, when a new output surface is
added, or when one of the referenced regulatory frameworks is
materially updated.

## Identifier classes and the NERC CIP-011 framing

The pseudonym vocabulary is **extensible by design**, but adding a new
identifier class is an ADR-grade decision because it changes the
privacy contract. Each addition must justify:

1. **What the class identifies** — what real-world thing the
   pseudonym stands in for (host, MAC, hostname, vendor, etc.).
2. **Why scrubbing it matters** — the threat model the class
   addresses. If the answer is "no operator would care if this leaked
   to the AI," the class probably shouldn't exist.
3. **How the leak detector enforces the contract** — most classes
   have a clean regex shape (IPv4 dotted-quad, MAC colon-hex);
   hostnames don't, so they're enforced by the map-value check.

**NERC CIP-011 (BES Cyber System Information).** Hostnames in
critical-infrastructure environments often fall under CIP-011 BCSI
because they identify the *function* and *location* of an asset. A
hostname like `ACME-SUB-LINE3-PLC` reveals that the asset is a PLC,
that it's at a specific substation/line, and that it belongs to a
named operator. Names like that are clearly more sensitive than the
private RFC 1918 IP they happen to use. Extracting hostnames *into*
the report without scrubbing them out of the AI payload would
*worsen* the compliance posture of the AI flow — which is why the
hostname scrub support is non-negotiable, not optional.

The same framing applies to future classes:
- **Vendor product strings / firmware versions** that name a specific
  fielded device (vs. generic vendor labels like "Siemens" — those
  stay preserved): would need a class.
- **Tag names from process protocols** (OPC UA browse names, etc.):
  almost always BCSI-equivalent, would need a class.
- **Engineering project / station names** appearing in S7Comm or
  ENIP-CIP traffic: same.

Each of these gets its own ADR amendment when implemented.

## Leak detector responsibilities

The leak detector that sits between the scrub layer and any AI call
runs **two checks**:

1. **Regex check** (`ensure_clean`) — IPv4, IPv6, and MAC patterns.
   Defense in depth: catches identifiers the scrub layer never knew
   about (a bug-class case where extraction was incomplete).
2. **Map-value check** (`ensure_no_map_values`) — verifies that no
   real value in the scrub map appears verbatim in the post-scrub
   text. This is the **primary** enforcement for hostname-class
   leaks, because hostnames don't have a clean regex shape (anything
   from `host42` to `LINE-3-PLC` is a valid hostname), so we can't
   regex-match them. We *can* check that the specific real values we
   observed don't appear in the payload we're about to send.

Both checks fail closed.

## Consequences

- New CLI: `scrub` and `unscrub` subcommands. The default no-subcommand
  invocation is gone — this is a v0.2 breaking change. README and
  CLAUDE.md updated.
- Test surface grows: snapshot tests now cover scrubbed markdown and the
  map JSON shape; round-trip property is asserted (`unscrub(scrub(x)) == x`).
- New dependency: `regex` (pulled in by `unscrub_text` for token matching).
- Pseudonym vocabulary becomes part of the public contract — adding new
  classes (`unit_NN`, etc.) is fine, but renaming or removing is a
  breaking change. Currently shipped: `host_NNN`, `mac_NNN`,
  `name_NNN`.
