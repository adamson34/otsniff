# Segmentation drift

Roadmap: **P1-13**. Composes two shipped features — cross-capture diff
(P1-3) and Zonewarden segmentation conformance (ADR-0013) — into a single
question: *did our segmentation posture change between two captures of the
same network?*

## Problem

`otsniff diff baseline.pcap current.pcap` already answers "what changed?"
for hosts, findings, roles, and the comms matrix. `otsniff analyze --policy
zones.yaml` already answers "does this capture conform to our documented
IEC 62443 zones/conduits?" Neither answers the longitudinal question a
62443 program actually asks of repeat scans:

> Since last quarter's capture, did new segmentation violations appear?
> Did any resolve? Did the count of IDMZ bypasses move? And is that a real
> behavioral change, or did we just re-author the policy in between?

Today the only way to get there is to run `analyze --policy` on both
captures and eyeball two conformance sections side by side — manual,
error-prone, and it can't tell a behavioral change from a policy edit.

The existing diff path does **not** close this gap on its own:

- The `zonewarden.*` findings are **rolled up by kind** (one finding for
  all IDMZ bypasses, one for all wrong-direction, one for deny-by-default
  — see `src/findings/zonewarden.rs`). Feeding conformance-aware findings
  through the existing `findings_new/recurring/resolved` classification
  therefore yields only coarse "bypasses present: yes → no" signal, never
  *which* flows started or stopped violating.
- Conformance **tallies** (allowed / intra-zone / external-endpoint
  counts) produce no findings at all — allowed flows aren't findings — so
  the diff can't see them move.
- Nothing compares the `policy_digest`, so a diff can't distinguish a
  behavioral regression from a policy revision.

## Decision

Add an optional **segmentation-drift** computation to the existing `diff`
subcommand, gated on a policy. When a policy is supplied, the diff runs
the Zonewarden conformance engine against **both** captures and emits a
new "Segmentation drift" section alongside the existing host/finding/flow
deltas.

Three things make this its own computation rather than a reuse of the
finding-diff path:

1. **Tally deltas** — per-metric baseline → current movement (allowed,
   intra-zone, distinct violating flows, IDMZ bypasses, no-matching-conduit,
   wrong-direction, multicast-exempt, external endpoints). These come
   straight off the two `ConformanceResult`s; findings can't express them.
2. **Per-violation deltas** — `violations_new` / `violations_resolved` /
   `violations_persisting`, matched on the **scrubbed** key
   `(kind, src_pseudonym, dst_pseudonym, dst_port, proto)`. This is the
   per-flow resolution the rolled-up findings throw away.
3. **Policy audit anchor** — the `policy_digest` is recorded in the output
   so a reader knows exactly which policy version the drift was measured
   against.

### One policy, held constant

Segmentation drift applies a **single** policy to **both** captures: it
holds the yardstick constant and varies the traffic. That is the only
analytically sound comparison — if the baseline and current captures were
scored against *different* policies, every delta would have two possible
causes (the network changed *or* the policy changed) with no way to
attribute it.

The policy-revision case has a cleaner answer that is still single-policy:
if `zones.yaml` was re-authored between captures, re-run **both** captures
against the new policy (the current source of truth) and diff that. So
there is deliberately no `--baseline-policy`/`--current-policy` surface and
no "policy changed between captures" comparison. (Diffing two *policies*
against one capture is a different feature — out of scope.) Because both
sides use the same policy, the two digests are identical by construction;
the digest is therefore a displayed audit anchor, not a comparison.

### CLI surface

Extend `Command::Diff` with a single `--policy` flag (do **not** add a new
subcommand — segmentation drift is a facet of a diff, exactly as the
conformance section is a facet of `analyze`):

```sh
otsniff diff baseline.pcap current.pcap \
  --baseline-map baseline.map.json --current-map current.map.json \
  --policy zones.yaml -o drift.html
```

- `--policy PATH` — the same policy is applied to both captures.
- Omitting `--policy` ⇒ no segmentation-drift section (today's diff
  behavior, unchanged).

### Data model (`src/diff.rs`)

`DiffInput<'a>` gains an optional conformance result per side:

```rust
pub struct DiffInput<'a> {
    pub observations: &'a Observations,
    pub map: &'a ScrubMap,
    pub findings: &'a [Finding],
    pub conformance: Option<&'a ConformanceResult>, // NEW
}
```

`Diff` gains an optional drift section (present only when both inputs carry
a conformance result):

```rust
pub struct Diff {
    // ... existing fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segmentation: Option<SegmentationDrift>, // NEW
}

pub struct SegmentationDrift {
    pub policy_digest: String,             // displayed audit anchor
    pub tally: Vec<TallyDelta>,            // one row per conformance metric
    pub violations_new: Vec<ViolationRef>,
    pub violations_resolved: Vec<ViolationRef>,
    pub violations_persisting: Vec<ViolationRef>,
}

pub struct TallyDelta {
    pub metric: String,     // "idmz_bypasses", "allowed", ...
    pub baseline: u64,
    pub current: u64,
    // direction derived in the view layer: current.cmp(&baseline)
}

pub struct ViolationRef {
    pub kind: String,       // "idmz_bypass" | "wrong_direction" | "deny_by_default"
    pub src_pseudonym: String,
    pub dst_pseudonym: String,
    pub dst_port: u16,
    pub proto: String,
    pub severity: String,   // "established" | "attempted"
}
```

**`ViolationRef` is the privacy-load-bearing type.** `zonewarden::types::
Violation` carries **raw** `src_ip`/`dst_ip` (the pure engine runs pre-scrub).
The drift builder MUST project every `Violation` into a `ViolationRef` whose
endpoints are pseudonyms resolved through the merged scrub maps
(`resolve_ip_to_pseudonym`, `src/diff.rs:330`) at construction time. The raw
`ConformanceResult` is **never** stored on `Diff` and never serialized — only
the pseudonymized projection is. See Scrub stance below.

### Matching violations across runs

`Violation.flow_index` is a dense index over each capture's
canonically-sorted flows (`src/segmentation/bridge.rs`) — it is **not**
stable across captures and must never be a match key. The match key is the
scrubbed tuple `(kind, src_pseudonym, dst_pseudonym, dst_port, proto)`,
mirroring `finding_diff_key` (`src/diff.rs:208`). Build the baseline and
current key sets; set difference gives new/resolved, intersection gives
persisting.

### Wiring (`src/cli.rs::run_diff`)

After the existing map-load + parse + findings steps, when `--policy` is
set:

1. `segmentation::run_conformance_path(policy_path, &flows)` for each side,
   reusing the exact path `analyze --policy` uses (`src/cli.rs:644`) with
   the one policy applied to both captures' flows.
2. Pass each `ConformanceResult` into the corresponding `DiffInput`.
   (Findings continue to come from `findings::run_all` — we deliberately do
   **not** switch the diff to `run_with_conformance`, so the existing
   finding deltas stay policy-independent and comparable run to run. The
   drift section owns all conformance-derived output.)
3. `diff::compute_with_multiplier` builds `Diff.segmentation` when both
   inputs have conformance.
4. Existing render-by-extension + fail-closed leak check + write path is
   unchanged; it already gates the rendered bytes (`src/cli.rs:436`).

## Output

### HTML (`templates/diff.html`, `src/report.rs`)

A "Segmentation drift" section after the findings deltas, shown only when
`Diff.segmentation` is present:

- **Policy anchor line.** A muted note recording the `policy_digest` the
  drift was measured against.
- **Tally table.** metric | baseline | current | ▲/▼/— (direction tinted:
  more violations/bypasses = worse = severity color; fewer = good).
- **Violation deltas.** Three lists (new / resolved / persisting), each row
  `kind · src_pseudonym → dst_pseudonym:port/proto · severity`. New IDMZ
  bypasses get Critical tint; resolved render in a "good news" style.

### Markdown (`src/report_md.rs`)

Mirror of the HTML: a `## Segmentation drift` section, the policy-anchor
line, a tally table, and three violation-delta lists. Deterministic sort.

### JSON

`Diff.segmentation` serializes natively (the struct derives `Serialize`,
like the rest of `Diff`). Absent key when no policy was supplied
(`skip_serializing_if`).

## Determinism

The `policy_digest` is order-independent (the bridge sorts flows
canonically — `src/segmentation/bridge.rs`, verified by
`digest_is_deterministic_and_flow_order_independent`) and, since one policy
scores both captures, identical on both sides by construction. The drift
builder adds no new ordering risk provided every output vector is sorted by
its scrubbed key before return — `tally` by a fixed metric order,
`violations_*` by `(kind, src_pseudonym, dst_pseudonym, dst_port, proto)`.
Same discipline as the existing diff vectors (`src/diff.rs:436+`).

## Scrub stance

### 1. What does this feature extract?

Nothing new off the wire. It consumes two `ConformanceResult`s already
produced by the shipped `analyze --policy` path, which are derived from
flows otsniff already observes. No new packet fields, no new protocol
parsing.

### 2. What does this feature render?

A new "Segmentation drift" section in the diff HTML, markdown, and JSON
outputs: integer tallies, the policy `policy_digest`(s), and per-violation
rows referencing host endpoints.

The host endpoints are the **only** identifier-bearing data, and they are
rendered exclusively as `host_NNN` pseudonyms via the merged scrub maps —
the same mechanism the rest of the diff already uses. The raw
`ConformanceResult` (which holds real IPs in its `Violation` rows) is never
serialized; only the pseudonymized `ViolationRef` projection reaches any
output surface.

### 3. What's the BCSI classification?

- **Tally counts** (integers) — not BCSI; no identifiers.
- **`policy_digest`** (SHA-256 of the *policy document*, not traffic) —
  Internal/Low. It's a hash of zone/conduit definitions the user authored,
  contains no observed network data, and is intended as a public audit
  anchor.
- **Violation endpoints** — same classification as every other host
  reference in the diff: High-BCSI in raw form, neutralized to `host_NNN`
  pseudonyms. Identical stance to existing diff host references.

### 4. What's the scrub stance?

- **Pseudonym class:** existing `host_NNN` only. **No new class**, so **no
  ADR-0006 amendment required.**
- **Leak detector coverage:** the rendered diff bytes already pass through
  the fail-closed leak detector before write (`src/cli.rs:436`) — regex
  (IP/MAC shapes) + map-value (every real value) checks. The drift section
  is covered by that existing gate as a backstop; the primary guarantee is
  that `ViolationRef` endpoints are pseudonymized at construction.
- **Test that enforces it:** a new invariant test builds a `Diff` with a
  `SegmentationDrift` whose underlying `Violation`s carry canary real IPs,
  serializes it to JSON/HTML/MD, and asserts none of the canary IPs appear
  in any output (mirrors `scrubbed_markdown_snapshot_does_not_leak_real_values`).

## Scope

**In scope:** the `diff --policy` surface; the `SegmentationDrift` data
model; HTML/MD/JSON rendering; tally deltas; per-violation
new/resolved/persisting deltas; the `policy_digest` audit anchor.

**Out of scope:**

- **Trend lines across >2 captures.** Drift is pairwise, like `diff`.
- **Suggesting policy edits from drift.** `zonewarden suggest` drafts a
  policy from one capture; reconciling drift into a revised policy is a
  separate feature.
- **Per-conduit utilization stats.** Beyond the conformance tally.
- **Rate normalization of tallies** for unequal capture windows. P1-11
  already tracks window-mismatch warnings for flow shifts; segmentation
  counts inherit that warning but are not rate-normalized here.

## Touched files

- `src/cli.rs` — `--policy` on `Command::Diff`; conformance runs +
  threading into `DiffInput` in `run_diff`.
- `src/diff.rs` — `conformance` field on `DiffInput`; `SegmentationDrift`,
  `TallyDelta`, `ViolationRef`; build + pseudonymize + sort.
- `src/report.rs` + `templates/diff.html` — the HTML section + views.
- `src/report_md.rs` — the markdown section.
- `tests/` — unit tests for matching/pseudonymization; a no-leak invariant
  test; snapshot tests for HTML + markdown drift sections.

## Test plan

- **Unit:** violation match key (new/resolved/persisting); `flow_index`
  explicitly *not* used for matching; tally delta direction.
- **Privacy invariant:** canary-IP no-leak across JSON/HTML/MD (see Scrub
  stance §4) — must block the build if a raw IP escapes.
- **Determinism:** same inputs in swapped order → identical
  `SegmentationDrift` (digest and sorted vectors).
- **Snapshot:** a deterministic two-capture fixture with a known policy →
  HTML + markdown drift sections, reviewed via `cargo insta`.
- **CLI smoke:** `diff --policy` end-to-end produces a report containing
  the drift section; absent `--policy` it does not.

## ADR?

No new ADR. This composes existing subsystems without an architectural
decision: no new dependency, no new crate boundary, no new pseudonym class,
no change to the privacy invariant. Single-policy-held-constant (see "One
policy, held constant" above) is the one notable design choice and is
captured here; this spec is the design contract.
