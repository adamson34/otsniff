# CLI Behavior Check: Map-Corruption Path (AC-005)

**Purpose:** AC-005 requires no observable behavior change from the crate
extraction. This check exercises `ScrubMap::validate()`'s map-corruption
detection (`PrivacyError::MapCorrupt`, routed to `OtError::Parse`, exit
code 70) through the live `otsniff unscrub` CLI path, distinct from the
leak-detector's `PrivacyError::Leak` path (routed to `OtError::Privacy`,
exit code 75). This proves both branches of the new hand-written `From`
impl described in AC-003 preserve their pre-extraction exit codes and
message shapes.

## Setup

A corrupted scrub map with an empty pseudonym key (mapping to a real IPv4
value) was written to a temp file:

```json
{"version":1,"created_at":"2026-01-01T00:00:00Z","ips":{"":"10.0.0.1"},"macs":{},"names":{}}
```

## Command

```
cargo run --quiet -- unscrub --map <corrupted-map.json> /dev/null
```

## Output

```
otsniff: pcap parse error: scrub map has empty pseudonym key for real value '10.0.0.1'; the map is corrupted (EC-001). Regenerate the map with `otsniff scrub`.
```

**Exit code:** `70`

## Verification

- The message is prefixed `"pcap parse error"` — this is `OtError::Parse`'s
  display prefix, confirming `PrivacyError::MapCorrupt` routes to
  `OtError::Parse` as specified in AC-003, not to `OtError::Privacy`
  (which would read `"privacy invariant tripped: ..."` and exit 75).
- Exit code `70` matches `OtError::Parse`'s pre-extraction exit code
  exactly — unchanged by the move.
- The diagnostic legitimately names the offending real value (`10.0.0.1`)
  in its message, as AC-003 specifies for `MapCorrupt` (a data-integrity
  fault, not a privacy-invariant trip — the whole point of `Leak`'s
  distinct label is that it must never show a raw value, whereas
  `MapCorrupt`'s diagnostic purpose requires showing it).
- No real IP, MAC, or hostname other than the corrupted map's own test
  value appears in the output, and no absolute filesystem path appears.

This confirms the map-corruption path behaves identically to
pre-extraction otsniff, exercised live through the CLI binary rather than
a unit test — the strongest form of AC-005 evidence for this branch of
the error boundary.
