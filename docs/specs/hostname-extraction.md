# Hostname extraction + NERC-CIP-aware scrub

## Problem

The asset inventory shows IPs and MACs. Real plant networks identify
hosts by name (`LINE-3-PLC`, `ACME-HMI-EAST`, etc.), and that's what
operators recognize on sight. Reading "10.10.10.10" tells the reader
*nothing* the rest of the report didn't already tell them. Reading
"LINE-3-PLC" connects the row to the operator's mental model of the
plant.

Hostnames also matter for the **privacy posture**. Under NERC CIP-011,
hostnames that identify critical assets fall under BES Cyber System
Information (BCSI). A name like `ACME-SUB-LINE3-PLC` is arguably BCSI
even though `10.10.10.10` is not — the name identifies the asset's
function and location. Extracting hostnames *without* scrubbing them
would actively *worsen* the AI flow's compliance posture.

So the scrub support is non-negotiable. Every hostname we extract goes
into the scrub map as a `name_NNN` pseudonym, the AI never sees the
real name, and the leak detector's responsibility extends to catching
hostname leaks.

## Decision

Add hostname extraction + scrub support in one PR. Two pieces:

1. **DHCP option 12 extraction.** Most plant networks use DHCP for
   non-controller hosts (HMIs, engineering workstations, historians).
   Option 12 ("Host Name") in DHCP DISCOVER / REQUEST / ACK packets
   gives us name-to-IP mapping cleanly. v0.1 of this feature ships
   DHCP only.
2. **Scrub layer extension.** New pseudonym class `name_NNN`. Builds
   alongside the existing `host_NNN` and `mac_NNN` classes. The scrub
   pipeline replaces hostnames before the AI sees the report; unscrub
   reverses; the leak detector's coverage extends to hostname-pattern
   detection (and a new map-value check that catches anything the
   regex misses).

mDNS (UDP/5353 PTR records) and NetBIOS Name Service (UDP/137 with the
half-byte encoded names) are deferred — both are real sources but
DHCP captures the most common case in industrial networks.

## DHCP parsing scope

DHCP packet layout (RFC 2131):

```
0       4       8      12      16      20      24      28
| op    | htype | hlen  | hops  | xid (4)               |
| secs (2)      | flags (2)     | ciaddr (4)            |
| yiaddr (4)    | siaddr (4)    | giaddr (4)            |
| chaddr (16, padded)                                   |
| sname (64)                                            |
| file (128)                                            |
| 0x63 0x82 0x53 0x63 magic cookie at offset 236        |
| options... (variable)                                 |
```

Options at 240+: each is `[code (1) | len (1) | data (len)]`, except
code 0x00 (pad) and 0xFF (end) which are 1-byte each.

Recognition algorithm:

- Detect DHCP traffic: UDP src or dst port 67 or 68
- Confirm magic cookie at offset 236
- Walk options
- If option code 12 (`Host Name`) is found: data is ASCII hostname
- If yiaddr (offset 16-19) is non-zero: associate hostname with yiaddr
- Else if ciaddr (offset 12-15) is non-zero: use ciaddr
- Else if option code 50 (`Requested IP Address`) is found:
  use that 4-byte IP

Results in `(IpAddr, String)` mapping that goes into
`obs.hostnames: HashMap<IpAddr, String>`.

Out of scope for this PR:

- mDNS PTR / SRV records (UDP/5353)
- NetBIOS Name Service (UDP/137 with half-byte encoded names)
- Reverse DNS lookups during the analysis (active, not passive)
- DHCPv6
- Validating hostnames against RFC 1123 syntax — we accept whatever
  the client sent; sanity-check for printable ASCII to avoid junk

## Scrub layer extension

`ScrubMap` gains:

```rust
/// pseudonym → real hostname
pub names: BTreeMap<String, String>,
```

Pseudonym format: `name_001`, `name_002`, ..., zero-padded to keep
sort order stable. Same vocabulary shape as `host_NNN` and `mac_NNN`.

`build_map_at` populates `names` from `obs.hostnames` values, sorted
alphabetically for deterministic snapshots.

`scrub_text` substitution: hostnames are added to the same forward map
as IPs and MACs (longer values replaced first).

`unscrub_text` regex extends to match `name_NNN` tokens — same shape
as the existing `host_NNN` and `mac_NNN`. Single regex update:
`\b(?:host|mac|name)_[0-9a-f]+\b`.

Leak detector gains a new check: `ensure_no_map_values(text, map)`
that iterates every real value (IPs, MACs, hostnames) in the map and
fails closed if any appear in the post-scrub payload. This is the
catch-all that handles hostnames specifically — they don't have a
clean regex pattern (a hostname could be anything from `host42` to
`acme.plant.local` to `LINE-3-PLC`), so the map-value check is what
keeps the privacy invariant honest for them.

The pre-existing `ensure_clean` (regex-based IPv4/IPv6/MAC check)
stays as a defense-in-depth measure for the bug case where the scrub
map didn't contain something it should have.

## Display

Inventory table grows a `Hostname` column:

| IP | Hostname | Zone | MAC | Vendor | Role | ... |
|----|----------|------|-----|--------|------|-----|
| `10.10.10.10` | `LINE-3-PLC` | OT | `00:1B:1B:...` | Siemens | PLC | ... |
| `10.10.10.20` | `—` | OT | `00:0E:8C:...` | Siemens | PLC | ... |

`—` for hosts without a known hostname (we didn't see DHCP for them).

In scrubbed reports, the column shows pseudonyms (`name_001`) instead
of real names.

## ADR update

ADR-0006 (Scrub/unscrub) gains a section explicitly naming NERC
CIP-011 and the hostname class. The current ADR text frames scrub as
"every IP and MAC" — needs updating to reflect that the pseudonym
vocabulary is extensible and the *list of identifier classes* is part
of the contract. Each new class addition is an ADR-grade decision.

## Test plan

- Unit tests on `parse::dhcp::parse(payload)` with raw byte fixtures
  for DHCP DISCOVER (no yiaddr, hostname in options), DHCP ACK
  (yiaddr set, hostname in options), and rejection of non-DHCP UDP
  payloads
- Snapshot fixture extended with synthetic hostname observations so
  the inventory rendering shows the new column populated
- `every_finding_has_a_non_empty_playbook` and the privacy invariant
  tests both extend to the new path
- New unit test on `ensure_no_map_values` that confirms it catches a
  hostname leak the regex check would have missed

## Out of scope

- mDNS / NetBIOS extraction (deferred to a follow-up PR)
- Reverse DNS during analysis (would require live network access, not
  passive)
- Editable scrub maps (a customer wanting to override generated
  pseudonyms with their own labels — different feature)
- DHCP option 81 (FQDN) — a DHCPv4 extension; we'd parse it the same
  way as option 12 but it's less commonly populated
- Locale / character-encoding handling for non-ASCII hostnames — we
  treat as bytes, will display non-printable as escaped
