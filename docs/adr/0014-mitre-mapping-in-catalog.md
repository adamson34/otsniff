# ADR-0014: MITRE ATT&CK for ICS mapping lives in the rule catalog

## Status
Accepted — implemented (S-12.01). All seven previously-unmapped detection rules
(`creds.*`, `creds.ldap_simple_bind`, `compat.smbv1`, `compat.stale_tls`,
`compat.weak_tls_cipher`, `boundary.dns_resolver`, `boundary.ntp_external`) now
carry a `ReferenceKind::MitreIcsAttack` reference, and every finding surfaces its
technique(s) in the HTML / markdown / JSON report by id-lookup from the catalog.

## Context
otsniff already modelled external references on each rule via
`RuleMetadata.references` (`src/findings/mod.rs`), and `ReferenceKind` already had
a `MitreIcsAttack` variant with a display-ready `label` (e.g.
`"T0859 — Valid Accounts"`) plus a `url`. Eight of the detection rules already
tagged a technique; seven did not, and no report surface (HTML/MD/JSON) surfaced
the technique at all — only `otsniff rules` / `docs/RULES.md` did.

ROADMAP item P1-6 proposed "every `Finding` gains a `technique_ids` field." Taken
literally, that would duplicate the technique mapping in two places: the runtime
`Finding` produced by a detector, and the static `RuleMetadata` in the catalog.
The two would then be free to drift — a detector could emit a `Finding` whose
`technique_ids` disagree with the catalog the `otsniff rules` command prints.

The report already had a precedent for the alternative: the per-finding
"Detection criteria" line is **not** stored on `Finding`. It is looked up at
render time from the catalog via `metadata_for(finding.id)`. The same id-lookup
seam can carry MITRE techniques.

## Decision
1. **MITRE technique data lives only in the rule catalog**
   (`RuleMetadata.references`, `ReferenceKind::MitreIcsAttack`) — the documented
   single source of truth that "can't drift" because it sits next to the detector.
   `Finding` gains **no** `technique_ids` field.

2. **Renderers surface techniques by id-lookup**, mirroring the existing `trigger`
   enrichment. A small helper, `findings::mitre_techniques_for(id)`, filters the
   catalog entry's `references` to `MitreIcsAttack` entries that carry a `url`,
   in `references` order. It returns an empty vec when the id isn't in the catalog
   (the same guard `trigger` uses; BC-3.06.002 guarantees fired findings always
   have a catalog entry). The HTML view pre-formats these into a
   `Vec<MitreLinkView>` so the template only iterates and anchors (ADR-0003); the
   markdown renderer emits a `**MITRE ATT&CK for ICS.**` line; the `--json`
   payload enriches each finding object with a `mitre_techniques` array via
   `findings::findings_json`.

3. **Asserting vs. supporting is expressed in the reference `label`, not the
   schema.** A technique that the rule's signal *asserts* (e.g.
   `T0859 — Valid Accounts` for a plaintext credential) carries a bare label; one
   the rule only *supports* as corroborating evidence (e.g.
   `T0866 — Exploitation of Remote Services (supporting)` for SMBv1) carries a
   `(supporting)` suffix. This avoids adding a relationship enum to `Reference`
   for a distinction that is purely presentational.

4. **A catalog-coverage test enforces the invariant going forward.** Every
   detection rule in `catalog()` must carry at least one well-formed
   `MitreIcsAttack` reference (`url` `Some`, matching
   `^https://attack\.mitre\.org/techniques/T0\d+/$`). The three policy-gated
   `zonewarden.*` rules (ADR-0013) are exempt: they are IEC 62443 segmentation-
   *conformance* verdicts, not adversary-behaviour detections, and ATT&CK for ICS
   models adversary *techniques* — network segmentation is a *mitigation* (M0930),
   not a technique. They keep their IEC 62443 `Spec` references instead.

## Consequences
- The technique mapping has exactly one home; `otsniff rules`, `docs/RULES.md`,
  and the per-finding report rows are all derived from it, so they cannot
  disagree.
- A new detector cannot silently ship without a MITRE mapping — the coverage test
  fails until one is added.
- The only output changes are additive: a MITRE row in each finding HTML card, a
  MITRE line in each finding's markdown, and a `mitre_techniques` array in the
  findings JSON, plus the regenerated `docs/RULES.md`. Asset-inventory,
  comms-matrix, and capture-summary output is byte-identical.
- The MITRE strings are constant English keyed by rule id — no observed values —
  so they are inert to the scrub layer and the fail-closed leak detector; the
  `invariant_no_real_values_reach_ai_provider` test continues to hold.

## Alternatives considered
- **A `technique_ids` field on `Finding` (the literal ROADMAP wording).**
  Rejected: duplicates the mapping onto the runtime finding, inviting drift
  between a fired finding and the catalog `otsniff rules` prints.
- **A `relationship: Asserting | Supporting` enum on `Reference`.** Rejected: a
  schema change for a presentational distinction the `label` suffix already
  conveys; it would also ripple through the catalog JSON and every existing
  reference.
- **Forcing the `zonewarden.*` conformance verdicts to carry a technique.**
  Rejected: there is no ATT&CK-for-ICS *technique* for a segmentation-policy
  violation (segmentation is mitigation M0930); a forced mapping would be
  semantically wrong and require an unverifiable ID.
