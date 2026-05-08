# Capture-source detector

## Problem

Every otsniff finding silently assumes the input PCAP is a SPAN/mirror
capture — i.e., a passive observation of an entire VLAN's traffic. PCAPs
that come from elsewhere (host-side `tcpdump`, TAP on a single link,
synthetic / replay) invalidate that assumption and change how findings
should be read:

- **Internet egress from OT** — if SPAN, real concern. If host-side `tcpdump`,
  it's just "the host I was running tcpdump on did this." Different
  conclusion entirely.
- **No HMI seen** — SPAN: possible coverage gap. Host-side: tautology.
- **MAC-sharing → gateway inference** (the kind Claude made on the 4SICS
  capture) is only valid for SPAN. On a `tcpdump` running *on the gateway
  itself*, every frame shows the gateway's MAC regardless of true L2
  source/destination, and the inference is confidently wrong.

The detector classifies the capture and surfaces the result in the report.
The AI prompt is updated to qualify topology inferences when the source
isn't SPAN.

## Heuristic

Walks the parsed packet stream once (already happens in `observe.rs`) and
counts:

- per-MAC frame appearances (frames where the MAC is src or dst)
- broadcast/multicast frame count (dst MAC is `ff:ff:ff:ff:ff:ff` or has
  the multicast bit set)
- distinct MACs seen
- total frames

| Pattern | Classification |
|---|---|
| One MAC appears in src OR dst on >95% of frames | **host-side `tcpdump`** (dominant MAC = the capturing host's NIC) |
| Top 2 MACs each appear on >95% of frames AND no other MAC contributes meaningfully | **TAP** on a single link |
| ≥10 distinct MACs AND no MAC > 60% of frames AND broadcasts present | **SPAN/mirror** |
| None of the above | **ambiguous** |

## Confidence

- **High** — pattern is unambiguous and ≥1,000 frames analyzed.
- **Medium** — pattern present but borderline (e.g., 80% dominance instead
  of 95%) OR fewer than 1,000 frames.
- **Low** — small captures, no clear pattern.

## Output

### In the report

A new line in the summary section:

```
- Capture source: probable SPAN (high confidence) — 47 distinct MACs,
  no host dominates, broadcasts present.
```

or

```
- Capture source: probable host-side tcpdump (high confidence) — 99.4%
  of frames involve MAC 70:71:BC:3A:0D:E8. Findings about "internet
  egress" or "missing HMI" should be read as "from this host's vantage
  point" not as a network-level claim.
```

The MAC in the human-facing report is real. In the AI-bound version,
the existing scrub pipeline replaces it with its pseudonym (`mac_NNN`)
because every MAC the detector references has already been observed
during `observe.rs` and is therefore in the scrub map.

### In the AI system prompt

When source is **not** SPAN, the system prompt gets an appended
qualification clause:

> "Capture-source qualifier: this capture appears to be {host-side / TAP /
> ambiguous}. MAC-based gateway inference is unreliable. Treat the asset
> inventory as biased toward the capturing host's peers, not as a
> complete view of the network. Do not infer L3 topology from shared
> MACs in this case."

When source is SPAN, no qualifier is added.

This is implemented as a dynamic prompt assembler that takes the static
`SYSTEM_PROMPT` const and appends the qualifier conditionally. Both
parts are snapshot-tested.

## Scope

**In scope:**

- L2/L3-only heuristic (MAC counting, broadcast detection)
- Classification surfaced in HTML report, markdown report, and AI prompt
- Tests against real fixtures (4SICS-20 → SPAN, Modbus.pcap → ambiguous
  due to small size, DNP3-Malformed → ambiguous due to fuzz pattern)

**Not in scope:**

- L7 / payload-based replay detection
- Synthetic-vs-real classification
- Time-correlation analysis (which would need timestamps and reference
  data we don't have)
- Multi-source capture detection (e.g., merged PCAPs from multiple
  vantage points)

## Implementation notes

- New module `src/capture_source.rs` with:
  - `enum CaptureSource { Span { .. }, HostSide { .. }, Tap { .. }, Ambiguous }`
  - `enum Confidence { High, Medium, Low }`
  - `struct Classification { source, confidence, frames_analyzed, note }`
  - `fn classify(obs: &Observations) -> Classification`
- `Observations` gains `mac_frame_counts: BTreeMap<[u8;6], u64>` and
  `broadcast_frames: u64`. Updated during `observe()`. Determinism:
  BTreeMap means iteration order is stable for snapshots.
- `prompts::system_prompt(classification: &Classification) -> String` —
  static base + conditional qualifier.
- Markdown and HTML renderers each grow one new line in the summary.
- Snapshot tests cover the new report shape and the dynamic prompt for
  each classification.
