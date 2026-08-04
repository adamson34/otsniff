# ADR-0015: Operator-declared trusted writers may lower finding severity

## Status
Proposed — spec written (`docs/specs/trusted-writer-allowlist.md`, P1-12), not
yet implemented.

## Context

The engineering-command rules (`ics.modbus_writes`, `ics.cip_engineering`,
`ics.s7_engineering`, `ics.dnp3_engineering`) fire on every engineering-class
call, because Modbus, CIP, S7Comm and DNP3 have no authentication and a passive
PCAP tool cannot distinguish an authorized SCADA master from an attacker.

On a real plant capture the same known-good EWS→PLC pair therefore produces a
High or Critical finding every run, forever. The May 2026 triage recorded this as
the highest-impact false-positive gap: not because the finding is wrong, but
because a report whose top finding is always the same expected pair trains the
reader to skim the section that would also carry an unexpected writer.

Every prior input to the findings layer has been *observed evidence* — packets,
or a declarative policy (ADR-0013) that the engine checks observed flows
against. A trusted-writer allowlist is different in kind: it is an operator
assertion about intent that the tool cannot verify, and it makes report output
depend on it.

## Decision

Accept unverified operator assertions as an input that can **lower** finding
severity, subject to four constraints:

1. **Assertions may only lower severity, never raise it and never suppress.**
   A declared pair still appears in the report, as an Info-severity finding
   (`ics.trusted_writer_activity`). There is no code path where declaring a
   trusted writer removes information from the report.

2. **The reduction is always visible.** The Info finding's summary states that
   severity was reduced by operator declaration, so a reader who did not run the
   command — an auditor, or a colleague reading the HTML months later — can see
   that an allowlist was in force and how many pairs it covered.

3. **Partition, never blanket-downgrade.** A finding mixing trusted and
   untrusted pairs keeps its original severity for the untrusted ones. Applying
   the downgrade to a whole finding would let a declaration for one pair mask an
   unexpected writer sharing the protocol — trading a false positive for a false
   negative, which for a security tool is the worse trade.

4. **The assertion is recorded as a digest, not as addresses.** The audit log
   gains a count and a SHA-256 over the canonicalized rule list, following the
   `policy_digest` precedent from ADR-0013, so two runs are comparable without
   the compliance artifact carrying host identifiers.

## Consequences

**We accept** that a hostile or careless operator can lower the severity of real
attacker traffic by declaring the attacker's IP. This is not a meaningful new
risk: the same operator chooses the capture, the `--ot-subnet` values, and
whether to read the report at all. Constraints 1–3 mean the traffic still
appears; only its ranking changes.

**We accept** that IPs are spoofable, so a match proves only that the packets
claimed those addresses. The rule catalog text must say this in plain language
rather than implying the traffic was authenticated — a reader who takes
`ics.trusted_writer_activity` as proof of authorization has been misled by us.

**We gain** a report whose engineering-command section is about *unexpected*
control-plane writes on repeat captures, which is the question the section is
supposed to answer.

**This does not open the door** to a general suppression framework. The decision
is scoped to the four engineering-command rules, where the false-positive
pressure is concentrated and the "who is the authorized writer" question has a
stable answer an operator actually knows. A generic `--suppress <rule-id>` would
need its own ADR and is closer in shape to P2-8 (user-defined rules), which the
roadmap deliberately holds at P2.

## Alternatives considered

**Fold the allowlist into the Zonewarden `zones.yaml` policy.** Rejected:
Zonewarden is opt-in via `--policy` and carries a far larger commitment (zones,
conduits, the IDMZ model). An operator wanting to quiet one known EWS pair would
first have to author a full IEC 62443 zone policy. The two features answer
different questions and should stay independently adoptable.

**Suppress matched findings entirely.** Rejected: it makes the report a function
of an unverifiable assertion in a way the reader cannot see, and it destroys the
longitudinal value of `diff` — a pair that stops being declared would appear as a
brand-new finding with no history.

**Do nothing; rely on the investigation playbook.** Rejected: that is the status
quo, and the playbook step "ask the on-shift control engineer whether X is the
authorized master" is precisely the question whose answer the tool currently
cannot retain between runs.
