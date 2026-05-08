# Scrub stance — template for new feature specs

Every feature spec under `docs/specs/` that adds an extractor, a new
field on `Observations`, a new rendered field, or a new output surface
**must** include a "Scrub stance" section. Copy the template below,
delete this preamble, and answer all four questions.

If the answer to any question is "I'm not sure," ask in the PR before
landing — the privacy invariant (ADR-0006) is non-negotiable.

This contract exists because:

1. Every new identifier we extract is a potential leak vector against
   the AI flow.
2. The audit at `docs/audits/scrub-audit-cip011.md` covers the
   currently-shipped surface. New features need to extend it, not
   silently bypass it.
3. Decisions about what's "BCSI enough to scrub" are easier to make
   at design time than after the field has shipped.

---

## Scrub stance

### 1. What does this feature extract?

List every new piece of data the feature reads off the wire or computes
from observations. Be specific — "a string from the protocol" is not
useful; "the device serial number from the EtherNet/IP Identity reply
attribute 7" is.

### 2. What does this feature render?

Where does the extracted data show up? Inventory column? Finding
evidence? Top flows? JSON output? AI prompt? List every output surface.

If the answer is "in-memory only, never rendered," say so — and
verify it stays that way (`#[serde(skip)]`, sentinel test, etc.).

### 3. What's the BCSI classification?

For each extracted field, classify against
`docs/audits/scrub-audit-cip011.md` (High / Medium / Low / Internal).

If the field doesn't obviously fit one of those classes, propose a
classification with reasoning. Borderline cases are OK to surface here
— better to discuss them in the spec than discover them in production.

### 4. What's the scrub stance?

For each extracted/rendered field, declare:

- **Pseudonym class** (existing `host_NNN` / `mac_NNN` / `name_NNN`,
  or a new class). New classes require an ADR-0006 amendment.
- **Leak detector coverage** (regex check / map-value check / both).
  Hostnames have no clean regex shape and rely on the map-value check
  — same applies to most High-BCSI string content.
- **Test that enforces it.** What unit / snapshot / invariant test
  proves the field doesn't reach any AI provider unscrubbed?

If a field is preserved (Low-BCSI: vendor name, FC label, etc.),
state that explicitly — "preserved, not scrubbed, because [reason]."
This is the audit trail.

---

## Example: hostname extraction (P0-3)

For reference, here's what filling this in looked like for the
hostname feature:

> **1. Extracts:** Host names from DHCP option 12 in DHCP Discover /
> Request / ACK packets, associated with the IP from yiaddr / ciaddr /
> option 50.
>
> **2. Renders:** Hostname column in the asset inventory (HTML and
> markdown). Stored on `Asset.hostname: Option<String>`. Also
> serialized in the `--json` payload via the inventory.
>
> **3. BCSI classification:** **High**. Hostnames in OT environments
> often identify the asset's function and location (`LINE-3-PLC`,
> `ACME-SUB-EAST`). NERC CIP-011 BCSI even when the IP is not.
>
> **4. Scrub stance:**
> - Pseudonym class: new `name_NNN`. ADR-0006 amended.
> - Leak detector coverage: map-value check (`ensure_no_map_values`)
>   — hostnames have no clean regex shape.
> - Test: `scrubbed_markdown_snapshot_does_not_leak_real_values`
>   asserts `ENG-WS-01` and `PLC-LINE3` from the fixture do not
>   survive scrub. `invariant_no_real_values_reach_ai_provider` runs
>   the map-value check on the AI-bound bytes.
