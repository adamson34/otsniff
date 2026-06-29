# ADR-0013: Zonewarden segmentation-conformance module

## Status
Proposed (v0.6 target)

## Context
`zonewarden` began as a separate tool: it takes a declarative IEC 62443
zone/conduit policy plus observed flows and classifies every flow as conformant
or violating, including the headline Purdue-3.5 IDMZ no-bypass check. Its core is
a pure, formally-verified Rust crate (7 Kani proofs over the resolver, classifier,
IDMZ truth table, multicast exemption, and tally arithmetic; ~96% mutation kill;
deterministic canonical-JSON SHA-256 policy digest).

In practice zonewarden and otsniff overlap heavily and uncomfortably:

- **Same input.** Both ingest OT/ICS network traffic. otsniff reads PCAPs
  natively (ADR-0001); zonewarden read a Zeek `conn.log`.
- **Overlapping findings.** zonewarden's most useful findings on real captures —
  OT→internet egress, insecure/cleartext protocols crossing zones, recon —
  are *already* produced by otsniff's zero-config rule catalog (`egress.*`,
  `creds.*`, `boundary.*`, `recon.*`), and otsniff goes deeper (payload-level,
  e.g. Modbus write commands) because it parses protocol content, not just the
  5-tuple.
- **Divergent unique value.** otsniff's unique surface is content triage, asset
  inventory + role inference, the privacy-scrubbed AI flow, and the HTML report.
  zonewarden's unique surface is the *declared* zone/conduit/IDMZ conformance
  model — "this flow violates the documented segmentation architecture" — plus
  policy-as-code and a deterministic, diffable audit artifact. Neither tool does
  the other's unique half.

Maintaining two binaries that consume the same captures and report a 30%-overlapping
set of findings is duplicated effort and a confusing story for users. otsniff is
the more complete product (native PCAP parsing, asset inventory, HTML report, AI
flow, releases at v0.5, distribution). The question is how to consolidate without
losing zonewarden's verified engine, its brand, or otsniff's "one-shot, zero-config"
identity.

otsniff already has the hooks for this:

- `observe.rs` produces a per-flow observation model (logical flow key, ADR-0009).
- `inventory.rs` infers host roles (PLC / HMI / EWS / historian / IT) and carries
  an `in_ot_zone` flag — a primitive of the zone model zonewarden generalises.
- `diff.rs` already does run-to-run drift; zonewarden's deterministic digest makes
  segmentation drift rigorous.
- Same dependency stack and MSRV (1.85, `thiserror` 2, `sha2` 0.11, `ipnet` 2.x),
  so the import carries no version conflicts.

## Decision

Fold zonewarden into otsniff as a named segmentation-conformance capability.
Specifically:

1. **otsniff is the host repository.** zonewarden's pure engine is imported, not
   the other way around; the standalone zonewarden repo is archived.

2. **The pure engine lands as a workspace sub-crate `crates/zonewarden`.** otsniff
   becomes a two-member workspace (the existing `otsniff` binary crate at the root
   + `crates/zonewarden`). Keeping it a *crate* boundary — not an `src/` module —
   preserves zonewarden's pure-core guarantee (no I/O, no serde, no sockets in the
   verified core) and keeps its Kani proofs isolated and intact. Package name:
   `zonewarden` (the prior `-core` suffix only meant something when it was its own
   repo).

3. **"Zonewarden" is retained as the user-visible feature name.** otsniff stays the
   product/binary; Zonewarden is the named segmentation feature inside it. The name
   appears in the CLI, the finding IDs, and the report.

4. **CLI surface — Option C (both a subcommand and an `analyze` flag):**

   ```sh
   # Integrated: triage report gains a "Zonewarden" section when a policy is given
   otsniff analyze plant.pcap -o report.html --policy zones.yaml

   # Focused: segmentation-only run
   otsniff zonewarden plant.pcap --policy zones.yaml

   # Bootstrap: draft a policy from the asset inventory + observed protocols
   otsniff zonewarden suggest plant.pcap > zones.yaml
   ```

   A new `Zonewarden` variant joins the existing `Analyze` / `Rules` / `Diff`
   subcommands. `analyze --policy` is the integrated path; `zonewarden` is the
   focused path; `zonewarden suggest` is the policy drafter.

5. **Segmentation verdicts become first-class `zonewarden.*` findings**, carrying
   the same severity, detection-criteria, and investigation-playbook treatment as
   every other rule:

   | Verdict | Finding ID | Severity |
   |---|---|---|
   | IDMZ bypass (OT↔IT, no DMZ hop) | `zonewarden.idmz_bypass` | Critical |
   | Reverse-direction conduit match | `zonewarden.wrong_direction` | High |
   | Deny-by-default (no conduit permits) | `zonewarden.deny_by_default` | High |

   The existing `egress.ot_to_internet` rule is **deduplicated** against the policy:
   when a `--policy` is supplied, OT→EXTERNAL flows are owned by the Zonewarden
   engine (which knows the declared zones precisely); without a policy, the existing
   subnet-based rule fires unchanged. Never both for the same flow.

6. **The report gains a "Zonewarden — Segmentation Conformance" section** (shown
   only when `--policy` is supplied): a Purdue-tiered topology diagram, the
   conformance summary (allowed / intra-zone / violations / bypasses), the echoed
   zone/conduit policy, and the deterministic `policy_digest` as the audit anchor.

7. **Consistency with ADR-0001 (no Zeek).** The Zonewarden engine consumes
   otsniff's *native* flow model via an in-memory `observe::Observation → zonewarden
   Flow` bridge — **not** a Zeek `conn.log`. otsniff's native flows are in fact a
   richer input than a conn.log: payload-confirmed service identity (real `modbus`,
   not a port heuristic) and a `conn_state` derived from otsniff's TCP tracking.
   zonewarden's old `zeek.rs` adapter is retained only as an optional
   `--flows conn.log` alternate input, not the primary path.

## Rationale

- **Stop maintaining two tools that ingest the same captures.** One binary, one
  repo, one CI gate. The duplicated egress/insecure-protocol findings collapse to a
  single owner.
- **The crate boundary is load-bearing, not cosmetic.** zonewarden's value rests on
  a pure core that *provably* performs no I/O; that is what the Kani proofs and the
  determinism guarantee depend on. Importing it as a sub-crate keeps that boundary;
  importing it as a plain `src/` module would silently allow serde/IO to creep into
  verified code.
- **Keeping the name preserves equity.** "Zonewarden" carries the formally-verified
  62443-engine story. Surfacing it as a subcommand and a report section keeps that
  brand attached to the capability rather than dissolving it into a generic
  "segmentation" label.
- **Option C, not just a flag, because the name deserves top billing.** A
  `zonewarden` subcommand makes the capability discoverable and gives the focused
  segmentation-only and `suggest` workflows a home, while `analyze --policy` keeps
  the "one report, both halves" story for the common case.
- **The merge unlocks policy auto-drafting nearly for free.** otsniff already infers
  host roles; that inference is ~80% of "what Purdue level is this subnet." Standalone
  zonewarden could never do this (no asset model). Inside otsniff, `zonewarden suggest`
  turns the asset inventory into a drafted `zones.yaml`, directly attacking
  zonewarden's biggest weakness (manual policy authoring).
- **Native flows are strictly better than conn.log.** The bridge upgrades service
  identity from heuristic to payload-confirmed and removes the external Zeek
  dependency the standalone tool carried — honoring ADR-0001.

## Module layout

```
otsniff/                          (host repo; the product)
├── Cargo.toml                    [package] otsniff  +  [workspace] members
├── src/
│   ├── cli.rs                    +Command::Zonewarden { analyze-flag + subcommand + suggest }
│   ├── observe.rs                +to_zonewarden_flows()  (the bridge)
│   ├── segmentation/policy.rs    YAML zone/conduit loader (effectful shell — serde)
│   ├── findings/                 +zonewarden.{idmz_bypass,wrong_direction,deny_by_default}
│   └── report*.rs / templates/   +"Zonewarden — Segmentation Conformance" section
└── crates/
    └── zonewarden/               ← imported zonewarden-core (pure, Kani-proven)
        ├── src/ {resolver, classifier, idmz, multicast, portset,
        │         aggregator, severity, digest, validator, types, errors}
        └── (7 Kani harnesses)
```

Import is history-preserving: extract `zonewarden-core/` from the zonewarden repo
with `git filter-repo --subdirectory-filter`, then graft it under
`crates/zonewarden/` via a subtree merge so the engine's commit history and
formal-proof lineage survive. The crate is self-contained, so the only edit inside
it is the package rename.

## Consequences

- otsniff converts from a single crate to a two-member Cargo workspace. CI
  (`ci.yml`, `mutants.yml`) picks up the new crate automatically; the 7 segmentation
  Kani harnesses are added to the existing `kani.yml` alongside the privacy proofs.
- The default `otsniff analyze plant.pcap` experience is unchanged — the Zonewarden
  section appears only when `--policy` is supplied, so the "one-shot, zero-config"
  identity is preserved.
- **Determinism must be guarded across the boundary.** otsniff's PCAP parse and
  asset inference are not order-stable; the Zonewarden engine is. The bridge must
  feed the engine canonicalised, sorted flow inputs so the `policy_digest` stays
  reproducible inside a non-deterministic host. This is the one real integration
  constraint.
- **`conn_state` fidelity** must come from otsniff's TCP tracking to keep severity
  grading honest (Zeek previously provided SF/REJ/S0 for free). Modest additional
  work in `observe.rs`.
- **License.** zonewarden is MIT, otsniff Apache-2.0. MIT→Apache-2.0 is compatible;
  the combined crate ships under Apache-2.0. The `crates/zonewarden` directory
  retains its MIT notice.
- The standalone zonewarden repo is archived read-only with a README pointer here;
  its `.factory/` artifacts are retained for provenance.
- Effort estimate: the pure core ports almost mechanically (it was built isolated);
  the real work is the `Observation → Flow` bridge, findings integration + egress
  dedup, the report section, and the `suggest` drafter — roughly 1–2 weeks, almost
  all of it in otsniff's findings/report layer rather than the engine.

## Alternatives considered

- **A new combined repository.** Rejected: discards otsniff's release history,
  CI, and brand identity (already at v0.5) for no benefit.
- **Make zonewarden the host, pull otsniff in.** Rejected: backwards — zonewarden
  is the engine; otsniff is the product with the user-facing surface, parsers,
  inventory, report, and distribution.
- **Keep two separate tools.** Rejected: perpetuates duplicated captures-in,
  overlapping findings-out, and a confusing two-binary story for the same users.
- **Import as an `src/segmentation/` module instead of a sub-crate.** Rejected:
  loses the enforced pure-core boundary that the Kani proofs and determinism rely
  on; serde/IO could leak into verified code.
- **Publish `zonewarden` to crates.io and have otsniff depend on it.** Rejected:
  with a single consumer and a solo maintainer, a published shared crate is pure
  overhead vs. vendoring the crate into the workspace.
- **Drop the "Zonewarden" name; merge verdicts into generic `segmentation.*`
  rules.** Rejected: discards the formally-verified-engine brand equity; the
  capability is distinctive enough to deserve a name.
