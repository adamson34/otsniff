# ADR-0012: Audit log auto-derives path from `-o`

## Status
Accepted (v0.3)

## Context
`analyze --ai` orchestrates a privacy-sensitive pipeline: scrub,
leak-check, invoke Claude, unscrub, embed result. Compliance auditors
and security-conscious operators need a chain-of-custody record of
each AI run: what pseudonymised text was sent, what response was
received, how many identifiers were scrubbed, and whether the leak
detector found any issues.

This chain-of-custody artifact is the audit log (`*.audit.json`).
The question is how users indicate where to write it.

Three approaches:

1. **Mandatory `--audit-log <PATH>` flag** — the run fails without it.
   Maximises audit coverage but is hostile UX for operators who just
   want a quick triage run. Would immediately get worked around with
   `/dev/null`.

2. **Optional `--audit-log <PATH>` flag, default off** — preserves
   UX but means the vast majority of AI runs produce no audit record.
   Compliance teams cannot rely on audit logs being present.

3. **Auto-derive from `-o`, override with `--audit-log <PATH>`** —
   every `--ai` run writes `<report-stem>.audit.json` in the same
   directory as the report, automatically. The user can override the
   path if they want audit logs in a dedicated directory.

## Decision
When `--ai` is set, the audit log is written automatically to
`<report-stem>.audit.json`. For example:

| `-o` value | Audit log path |
|---|---|
| `report.html` | `report.audit.json` |
| `output/site-a.html` | `output/site-a.audit.json` |
| `results/2026-05-11.html` | `results/2026-05-11.audit.json` |

The `--audit-log <PATH>` flag is supported as an override for users
who want to direct audit logs to a centralised directory (e.g.,
`/var/log/otsniff/`). Without `--ai`, no audit log is written,
regardless of whether `--audit-log` is passed.

## Rationale

- **Audit logs should be the default, not the exception.** Every time
  a user runs `analyze --ai`, plant-network data (even pseudonymised)
  is crossing the boundary to an AI system. That crossing should always
  be logged. Making the audit log opt-in means operators will skip it
  under time pressure.
- **Pairing the audit log with the report is semantically correct.**
  The audit log describes the specific AI run that produced the report.
  Keeping them in the same directory with matching stems makes the
  relationship obvious without a separate manifest file.
- **No extra flag to remember.** The `analyze` subcommand already
  requires `-o`. Deriving the audit log from that value adds no new
  cognitive overhead. The user says "write my report to `report.html`"
  and gets `report.audit.json` for free.
- **Override available.** Compliance environments that centralise audit
  logs (e.g., a read-only report share + a separate writable audit
  directory) can use `--audit-log` to redirect. This is an explicit
  opt-in override, not the default path.

## Audit log contents

The JSON audit log contains:

```json
{
  "version": 1,
  "run_id": "<uuid-v7>",
  "timestamp": "<rfc3339>",
  "pcap": "<input-path>",
  "report": "<output-path>",
  "scrub": {
    "host_count": N,
    "mac_count": N,
    "name_count": N,
    "bytes_scrubbed": N
  },
  "leak_check": {
    "passed": true,
    "regex_patterns_checked": N,
    "map_values_checked": N
  },
  "ai": {
    "provider": "claude-cli",
    "model": "<model-string or null>",
    "prompt_bytes": N,
    "response_bytes": N,
    "duration_ms": N
  }
}
```

No real IPs, MACs, or hostnames appear in the audit log — it records
counts and sizes, not the scrubbed values themselves. This means the
audit log is itself safe to store alongside a report that will be shared.

## What is not in the audit log

- The actual prompt text (it contains pseudonyms but is still large;
  users who need it can reconstruct it from the scrubbed report + the
  system prompt in `src/ai/prompts.rs`).
- The AI response text (same reasoning; it is embedded in the HTML report).
- Real IP/MAC/hostname values (enforced by the leak detector; the
  audit log construction happens after leak-check passes).

## Alternatives considered

- **Embed audit data in the HTML report** — would eliminate the separate
  file. Rejected: the audit log needs to be machine-parseable (for
  future tooling that aggregates logs across runs), not human-readable
  HTML. Embedding both in the HTML would require an invisible `<script
  type="application/json">` block, which conflicts with the XSS defense
  in ADR-0011.
- **Always write the audit log, even without `--ai`** — would produce
  an empty or near-empty log for rules-only runs. Confusing and wasteful.
  The audit log is specifically a record of AI interaction; without `--ai`
  there is nothing to audit.
- **Write to a fixed system path** (`~/.local/share/otsniff/audit/`) —
  breaks the self-contained file-pair design and requires creating
  directories in user home. Confusing for users who don't know to look
  there.

## Consequences

- Running `otsniff analyze capture.pcap -o report.html --ai` always
  produces both `report.html` and `report.audit.json`. Documentation
  and the README must note this clearly.
- If the report directory is read-only (unlikely but possible), the
  audit log write fails and the run aborts with a clear error message.
  This is intentional: failing to write the audit log means the chain
  of custody is broken; the run should not silently succeed.
- `--audit-log <PATH>` is a valid override; if specified, the auto-derived
  path is not used and the user-supplied path is used instead.
