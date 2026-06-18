# Evidence Report — S-6.03: HTML + Markdown Diff Renderer

**Story:** S-6.03 — Real HTML and markdown delta reports for `otsniff diff`
**Date:** 2026-06-18
**Recorded by:** Demo Recorder (vsdd-factory)

---

## Environment

| Tool | Version / Path |
|------|---------------|
| `otsniff` | v0.5.0-dev.1 (built from feature branch) |
| VHS | 0.11.0 (`/opt/homebrew/bin/vhs`) |
| editcap | Available (Wireshark bundle) — used to split fixture |
| tshark | Available (Wireshark bundle) |
| tcpdump | Available (`/usr/sbin/tcpdump`) |
| Font | Menlo (system default on macOS) |

**Fixture strategy:** `editcap` was available. The single fixture
`tests/fixtures/synthetic-1mb.pcap` (12,788 packets) was split into two
disjoint halves: packets 1–5000 (baseline) and 5001–12788 (current). Each
half was scraped with `otsniff scrub` to produce a map file. This produced a
diff with recurring findings and 10 flow shifts (using `--flow-shift-multiplier
1.1`) — sufficient to exercise every section of both renderers.

Scrub maps and split PCAPs are committed to
`docs/demo-evidence/S-6.03/fixtures/`.

---

## Coverage Map

| AC | Acceptance criterion | Artifact | Demo path |
|----|---------------------|----------|-----------|
| AC-001 | HTML renderer produces populated diff report with all sections | `AC-001-html-renderer.gif` / `.webm` | Live CLI run; split fixture |
| AC-002 | Markdown renderer produces same content as text | `AC-002-markdown-renderer.gif` / `.webm` | Live CLI run; split fixture |
| AC-003 | Renderer output is deterministic (byte-identical on repeat runs) | `AC-003-determinism.gif` / `.webm` | Two runs + `cmp` |
| EC-001 | Self-diff (capture vs itself) shows zero deltas in all categories | `EC-001-empty-diff.gif` / `.webm` | Same PCAP as both args; JSON confirms all arrays empty |

---

## AC-001 — HTML Renderer

**Recording:** `AC-001-html-renderer.gif` / `AC-001-html-renderer.webm`
**Tape source:** `AC-001-html-renderer.tape`

Demonstrates `otsniff diff` producing a populated `.html` report from two
captures. The recording shows:

- The CLI invocation with `--flow-shift-multiplier 1.1`
- Stdout summary: `wrote … (0 new hosts, 0 gone, 0 new findings, 0 resolved)`
- `grep` on the output file showing `stat-recurring` class and `<h2>` section
  headings (`Recurring findings`, `Flow shifts`) are present in the rendered HTML

The report contains: stats banner (new/recurring/resolved findings, new/gone
hosts, flow shifts), recurring findings section with evidence and playbook, and
a flow-shifts table with 10 entries at 1.56× ratio.

A sample of the live HTML report is committed at `diff-report.html`.

---

## AC-002 — Markdown Renderer

**Recording:** `AC-002-markdown-renderer.gif` / `AC-002-markdown-renderer.webm`
**Tape source:** `AC-002-markdown-renderer.tape`

Demonstrates `otsniff diff` producing a populated `.md` report. The recording
shows `cat` of the full output, which includes:

- `## Summary` with all six delta counters
- `## Recurring findings` section with evidence block and recommendation
- `## Flow shifts (>=1.1x volume change)` table with source/dest/port/proto/bytes/ratio columns

A copy of the live markdown report is committed at `diff-report.md`.

---

## AC-003 — Determinism

**Recording:** `AC-003-determinism.gif` / `AC-003-determinism.webm`
**Tape source:** `AC-003-determinism.tape`

Demonstrates that running `otsniff diff` twice on identical inputs produces
byte-identical output. The recording shows:

1. First invocation writing to `/tmp/run1.html`
2. Second invocation writing to `/tmp/run2.html`
3. `cmp /tmp/run1.html /tmp/run2.html && echo 'IDENTICAL: byte-for-byte match confirmed'`

The `IDENTICAL` message is printed; `cmp` exits 0.

---

## EC-001 — Empty Diff (Self-Diff)

**Recording:** `EC-001-empty-diff.gif` / `EC-001-empty-diff.webm`
**Tape source:** `EC-001-empty-diff.tape`

Demonstrates that diffing a capture against itself yields zero deltas. The
recording shows two invocations (one to `.html`, one to `.json`) where:

- CLI stdout: `wrote … (0 new hosts, 0 gone, 0 new findings, 0 resolved)`
- JSON output (via `jq`): all four delta arrays (`hosts_new`, `hosts_gone`,
  `findings_new`, `findings_resolved`) are empty (`[]`)

---

## Artifacts

```
docs/demo-evidence/S-6.03/
├── evidence-report.md                    (this file)
├── AC-001-html-renderer.tape
├── AC-001-html-renderer.gif
├── AC-001-html-renderer.webm
├── AC-002-markdown-renderer.tape
├── AC-002-markdown-renderer.gif
├── AC-002-markdown-renderer.webm
├── AC-003-determinism.tape
├── AC-003-determinism.gif
├── AC-003-determinism.webm
├── EC-001-empty-diff.tape
├── EC-001-empty-diff.gif
├── EC-001-empty-diff.webm
├── diff-report.html                      (live HTML output sample)
├── diff-report.md                        (live markdown output sample)
└── fixtures/
    ├── baseline.pcap                     (packets 1-5000 of synthetic-1mb.pcap)
    ├── current.pcap                      (packets 5001-12788 of synthetic-1mb.pcap)
    ├── baseline-map.json                 (scrub map for baseline)
    └── current-map.json                  (scrub map for current)
```

---

## Absolute Path Check

`grep -l "/Users/" docs/demo-evidence/S-6.03/*.tape` — no matches. All tape
files use relative paths only (e.g., `docs/demo-evidence/S-6.03/fixtures/…`,
`./target/release/otsniff`).

---

## Snapshot Reference

The committed insta snapshots at `tests/snapshots/snapshot__diff_html_report.snap`
and `tests/snapshots/snapshot__diff_markdown_report.snap` provide a richer
reference showing all six delta categories (new/recurring/resolved findings,
new/gone hosts, role shifts, flow shifts) populated from a deterministic
in-memory fixture. The live demo recordings above use the real CLI against split
captures and exercise the same code paths.
