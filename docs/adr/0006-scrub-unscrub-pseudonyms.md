# ADR-0006: Scrub / unscrub for AI-assisted triage

## Status
Accepted (v0.2)

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

`<class>_<index>` where class ∈ `{host, mac}` and index is decimal,
zero-padded to 3 digits. The format is regex-safe:
`\b(?:host|mac)_[0-9a-f]+\b`. New identifier classes (e.g., `unit_NN` for
Modbus unit IDs in v0.3) extend the prefix vocabulary, not the format.

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

## Consequences

- New CLI: `scrub` and `unscrub` subcommands. The default no-subcommand
  invocation is gone — this is a v0.2 breaking change. README and
  CLAUDE.md updated.
- Test surface grows: snapshot tests now cover scrubbed markdown and the
  map JSON shape; round-trip property is asserted (`unscrub(scrub(x)) == x`).
- New dependency: `regex` (pulled in by `unscrub_text` for token matching).
- Pseudonym vocabulary becomes part of the public contract — adding new
  classes (`unit_NN`, `name_NNN`, etc.) is fine, but renaming or removing
  is a breaking change.
