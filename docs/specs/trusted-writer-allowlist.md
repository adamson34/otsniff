# Trusted-writer allowlist (P1-12)

**Status:** spec — not yet implemented.
**Roadmap item:** P1-12 (M).
**ADR:** [ADR-0015](../adr/0015-operator-declared-trusted-writers.md) records the
decision to let unverified operator assertions change finding severity.

## Problem

The engineering-command rules — `ics.modbus_writes`, `ics.cip_engineering`,
`ics.s7_engineering`, `ics.dnp3_engineering` — fire on *every* engineering-class
call. That is correct: Modbus, CIP, S7Comm and DNP3 have no authentication, so
any host that reaches a controller can change plant state, and the tool cannot
tell an authorized SCADA master from an attacker.

But every real plant has a handful of well-known authorized writers. On those
captures the rule fires High or Critical every single run, and the playbook's
first real step is "ask the on-shift control engineer whether X is the authorized
Modbus master." The analyst answers that same question every quarter, for the
same pair, and nothing in the tool remembers the answer.

The roadmap records this as the highest-impact false-positive gap found in the
May 2026 triage.

The failure mode is not that the finding is wrong. It is that a report where the
top finding is always the same known-good EWS→PLC pair trains the reader to skim
past the section that would also carry a genuinely unexpected writer.

## Non-goals

- **Not authentication.** A trusted-writer rule is an operator assertion about
  IPs. IPs are spoofable and this is a passive PCAP tool; the declaration says
  "I expect this pair," not "this pair is verified." ADR-0015 covers why we still
  accept it.
- **Not suppression.** Declared pairs stay in the report. See D2.
- **Not a general finding-suppression framework.** Scoped to the four
  engineering-command rules. A generic `--suppress <rule-id>` is a different,
  larger feature (and closer to P2-8's user-defined-rules Pandora's box).

## Design decisions

### D1 — Config surface: repeatable CLI flag, not the Zonewarden policy

```
--trusted-writer SRC=DST:PROTO
```

Repeatable, following the existing `--ot-subnet` precedent (`Vec<T>` on the clap
struct, four subcommands already do this).

**Rejected: folding into `zones.yaml`.** Zonewarden's policy is opt-in via
`--policy` and carries a much larger commitment — zones, conduits, the IDMZ
model. Coupling engineering-command tuning to it would mean an operator who
wants to silence one known EWS pair must first author a full 62443 zone policy.
The two features answer different questions and should stay independently
adoptable.

**Deferred: a YAML file surface.** A plant with dozens of authorized pairs will
want `--trusted-writers writers.yaml`. That is additive and can land later
without changing the semantics below; the flag is the smaller first step and
covers the "handful of well-known writers" case the roadmap describes.

### D1a — Grammar

```
SRC  = IPv4/IPv6 address or CIDR
DST  = IPv4/IPv6 address or CIDR
PROTO = modbus | cip | s7 | dnp3 | any
```

CIDR on both sides is deliberate: the common shape is one engineering
workstation writing to a whole rack or subnet of controllers
(`10.20.0.5=10.20.0.0/24:modbus`), and forcing one flag per PLC would make the
feature unusable at the scale that motivates it.

Parse failures are a usage error (`OtError` variant, exit 2) with the offending
argument echoed — a typo'd allowlist that silently matches nothing is worse than
no allowlist, because the operator believes a pair is declared when it is not.

### D2 — Partition, do not downgrade the whole finding

This is the load-bearing decision.

Each engineering finding today rolls up *all* client→server pairs for its
protocol into one `Finding`. The roadmap sketch — "severity INFO instead of
HIGH" — is right for a finding whose pairs are *all* trusted, but applying it
to a finding that mixes trusted and untrusted pairs would bury a genuinely
unexpected writer inside an Info-severity finding. That converts a
false-positive problem into a false-negative one, which is strictly worse.

So the detector partitions its pairs:

| Pairs observed | Emitted |
|---|---|
| All untrusted | Existing finding, unchanged id + severity logic |
| Mixed | Existing finding covering **untrusted pairs only** (severity computed from those pairs alone) **plus** the Info finding for the trusted ones |
| All trusted | Only the Info finding — the High/Critical finding does not fire |
| None | Nothing (unchanged) |

Note the severity interaction: `ics.modbus_writes` escalates High → Critical
when any source is outside the OT subnets. That escalation must be computed over
the untrusted pairs only, or a single trusted external writer would keep the
finding Critical forever.

### D3 — One new rule id, not four

Trusted activity rolls up into a single new catalog rule spanning all four
protocols:

```
ics.trusted_writer_activity   (Info)
```

Rather than a `_trusted` variant per protocol, which would take the catalog from
23 rules to 27 for what is an annotation rather than a distinct detection.
Evidence lines carry the protocol and the rule that matched:

```
modbus: ENG-WS-01 (10.20.0.5) -> PLC-LINE3 (10.20.0.10) : fc=0x10 (Write Multiple Registers)  [trusted-writer 1]
s7:     ENG-WS-01 (10.20.0.5) -> PLC-LINE4 (10.20.0.11) : 0x1A (Block Download)                [trusted-writer 2]
```

The rule is referenced by **1-based declaration index**, not by echoing the raw
CIDR — see the scrub stance below for why.

`RuleMetadata.trigger` must state plainly that this rule reflects an operator
assertion and is not evidence that the traffic was authenticated.

### D4 — Audit log records a digest, not the rules

The privacy-ledger audit log currently contains no real identifiers. Writing
raw trusted-writer CIDRs into it would break that property for a file that is
explicitly a compliance artifact.

Following the `policy_digest` precedent from ADR-0013, the audit log gains:

```json
"trusted_writers": { "count": 3, "digest": "sha256:…" }
```

The digest is over the canonicalized rule list (sorted, normalized CIDR text) so
two runs can be compared for "was the same allowlist in force?" without the file
carrying the addresses.

## Behaviour on the report

- The Info finding renders in the normal findings list, sorted last by the
  existing severity ordering.
- Its summary states the count of suppressed pairs and that severity was reduced
  by operator declaration, so a reader who did not run the command still learns
  that an allowlist was applied.
- A run with `--trusted-writer` that matches **nothing** emits a warning to
  stderr naming the unmatched declarations. A stale allowlist referencing a
  decommissioned host should be visible, not silent.

## Testing plan

Per CLAUDE.md, deterministic `Observations` fixtures — not real PCAPs.

1. **Unit, parser:** valid forms (IP, CIDR, v6, each proto, `any`), and rejects
   (`missing =`, bad CIDR, unknown proto, empty). Round-trip on the canonical
   digest input.
2. **Unit, matcher:** src/dst inside and outside CIDR; `any` matching all four
   protocols; a rule for one protocol not matching another.
3. **Detector, the D2 matrix:** one fixture per row — all-untrusted, mixed,
   all-trusted, none. The mixed case asserts the High finding's evidence contains
   only untrusted pairs, and that the Critical escalation does not fire on a
   trusted external source.
4. **Snapshot:** HTML + markdown + JSON for the mixed case (`cargo insta review`).
5. **Privacy invariant:** extend
   `invariant_no_real_values_reach_ai_provider` with a fixture carrying a
   trusted-writer declaration for a host **not present in the capture**, and
   assert the AI-bound bytes are clean. This is the regression test for the leak
   vector identified below.
6. **Catalog sentinel:** the existing tests already require every fired id to
   appear in the catalog; `docs/RULES.md` regenerates to 24 rules.

## Scrub stance

Per `docs/specs/scrub-stance-template.md`.

### 1. What does this feature extract?

Nothing off the wire. This is the first otsniff feature whose new identifiers
arrive from the **command line** rather than from the capture: source and
destination IPs/CIDRs and a protocol token, supplied by the operator.

It reads existing `Observations` fields only (`modbus_events`, `enip_events`,
`s7_events`, `dnp3_events` — the `src`/`dst` already used by these detectors).

### 2. What does this feature render?

- Finding evidence for `ics.trusted_writer_activity` — endpoints rendered via
  the existing `host_label(ip, obs)` helper, plus a 1-based rule index.
- Finding summary — counts only.
- stderr warning for unmatched declarations (not a report surface).
- Audit log — count + digest only (D4).

**Deliberately not rendered: the raw declaration text.** This is the whole
reason for the index-based reference in D3.

### 3. What's the BCSI classification?

**High**, same as any host identifier — an operator-declared pair is arguably
*more* sensitive than an observed one, because it asserts which host is the
authorized controller writer. That is exactly the "which asset matters" signal
CIP-011 BCSI is concerned with.

### 4. What's the scrub stance?

**Pseudonym class:** existing `host_NNN`. No new class, so no ADR-0006
amendment.

**The leak vector, stated plainly.** The scrub map is minted from *observed*
values. A trusted-writer declaration may name a host that never appears in the
capture (a typo, or a decommissioned EWS). If such an address were rendered into
the report, it would not be in the map, so `ensure_no_map_values` would not
catch it.

It would still fail closed: `ensure_clean`'s IPv4/IPv6 regex scan runs over the
AI-bound bytes and would abort the run. But "the `--ai` run aborts with a leak
error" is a bad outcome for a legitimate typo.

**The design closes this by construction:** only endpoints that were *actually
observed in a matched event* are rendered, and every such endpoint is by
definition in the scrub map. An unmatched declaration renders nowhere — it
surfaces only as the stderr warning, which is not an AI-bound surface. The rule
index in evidence carries no address.

**Leak detector coverage:** both. Map-value check covers the rendered endpoints
(they are observed hosts); the regex check remains as the fail-closed backstop
for any future code path that renders a declaration directly.

**Test that enforces it:** testing-plan item 5 — a declaration for an
unobserved host, asserting clean AI-bound bytes.

## Open questions

1. **Should a trusted pair suppress the `recon`/`modbus_unit_id_sweep` rules
   too?** A trusted master legitimately sweeping unit IDs is plausible. Deferred:
   the roadmap scopes P1-12 to engineering commands, and sweep-from-a-trusted-host
   is still worth an analyst's eye.
2. **Should `diff` treat an allowlist change as drift?** P1-13 does this for
   `policy_digest`. The D4 digest makes the same treatment possible for trusted
   writers, but it is a `diff` change and belongs with that feature, not here.
