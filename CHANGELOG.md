# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **Packs — optional components** (P2-10, ADR-0019): the installer gives
  you the core binary; everything else is a pack you add when you want it.
  `curl … | sh -s -- --packs web` at install time, or `otsniff pack list /
  add <name> / remove <name>` any time after. A pack is a separate binary
  `otsniff-<name>` published as its own release artifact and installed
  next to the core one; an installed pack runs as a subcommand
  (`otsniff web --port 7878`) the way `git foo` runs `git-foo`, resolving
  sibling-of-the-running-binary before `PATH`. `pack list` works offline;
  `pack add` verifies the artifact's SHA-256 before installing and shells
  out to `curl`/`tar` rather than embedding an HTTP client — it never
  pipes a downloaded script to a shell. Catalog today: `web`.
- **`otsniff-web` — local web companion app** (P2-9, ADR-0018, new
  workspace crate): `cargo run -p otsniff-web -- --port 7878 --data-dir
  ./otsniff-web-data` starts a `127.0.0.1`-only web UI — upload a PCAP,
  run the same rules-based `analyze` pipeline in-process (no
  subprocess), view the report in-browser, and browse a dashboard of
  past runs with HTML/JSON downloads. `axum`/`tokio` stay entirely off
  the CLI's own dependency tree (new crate boundary, same pattern as
  `zonewarden`/`otsniff-privacy`); the core analyze pipeline stays fully
  synchronous (ADR-0008 untouched) — the web crate's async layer calls
  it via `spawn_blocking`. `--ai` support, diffing past runs, and direct
  Anthropic API integration are deliberately deferred past v1; see
  `docs/ROADMAP.md` P2-9.
- **`creds.default_or_weak_credentials` finding** (P2-3, partial, Critical):
  fires on an FTP anonymous login, or an HTTP Basic password that's empty
  or matches a small watchlist of textbook-weak values (admin, password,
  123456, ...) — a stronger signal than generic cleartext-credential
  exposure, since these are guessable without ever capturing the traffic.
  Builds entirely on already-captured `cred_events`, no new protocol
  parsing. Evidence states only the matched *category*, never the raw
  captured username/password — see `docs/ROADMAP.md` P2-3 for what's
  deferred (Telnet, Siemens S7 default password, suspicious DNS, and
  hard-coded Modbus/S7 attack patterns all need new protocol parsing or
  careful external sourcing this story doesn't add). Rule catalog now
  lists **26** rules.
- **`otsniff bundle` / `unbundle`** (P2-7, ADR-0017): `bundle <report-stem>
  -o bundle.age --passphrase-env VAR` packs `<stem>.html` +
  `<stem>.map.json` + `<stem>.audit.json` (whichever exist) into one
  `age`-encrypted file; `unbundle` reverses it. Moves the BCSI-at-rest
  handling commitment (NERC CIP-011 alignment) from "guidance" to
  "default behavior" — closes the at-rest exposure window between
  `scrub`/`analyze --ai` and whenever the operator protects the output
  themselves. The passphrase is always read from a named environment
  variable, never accepted as a bare CLI argument (shell-history / `ps`
  visibility). `unbundle` refuses to extract any entry whose stored name
  isn't a bare filename, so a maliciously crafted bundle can't
  path-traverse on extract. New dependency: `age` (MIT/Apache-2.0).
- **Ollama local AI provider** (P2-6): `analyze --ai --provider ollama
  --model <name>` runs the AI analysis and augment passes through a local
  `ollama run <model>` instead of the Claude Code CLI, fulfilling the
  air-gap promise from ADR-0007 for operators who cannot use any external
  AI service. `--model` is required for this provider (no meaningful
  default across local installs) — omitting it is a clear usage error.
  Reuses the existing scrub → leak-check → unscrub pipeline and
  verbose-progress heartbeat unchanged; only the subprocess invocation
  differs.
- **`otsniff slice` subcommand** (P1-7, partial): `slice <PCAP> -o out.pcap
  --host IP` / `--flow SRC=DST:PORT` (repeatable, OR-matched, at least one
  required) extracts a small PCAP containing only matching packets,
  copied verbatim from the source file — not reconstructed from decoded
  fields, so checksums and unusual framing survive. Closes the loop with
  Wireshark/tshark/a vendor's support team without hand-filtering a
  multi-gigabyte capture. `--finding <ID>` (slice by which packets
  contributed to a specific finding) is not yet implemented — see
  `docs/ROADMAP.md` P1-7 for why it's a separate, larger follow-up.
- **Spoofed-source flood detection + inventory render cap** (P1-10): new
  `attack.spoofed_sources` (High) finding fires when more than 500
  distinct source IPs match the spoofed-source fingerprint — exactly one
  packet sent, zero received in reply, no MAC ever captured, no protocol
  enrichment. DoS captures with randomized source addresses (SYN flood,
  ping flood) can otherwise produce inventories with 10k+ "hosts" that
  drown the real ones out. The asset inventory table (HTML and markdown)
  is now capped to the top 100 hosts by traffic once the inventory
  exceeds that size, with a note naming how many low-volume hosts were
  omitted; the report's host-count stat stays the full, uncapped total.
  Rule catalog now lists **25** rules.
- **Trusted-writer allowlist** (P1-12, ADR-0015): `analyze --trusted-writer
  SRC=DST:PROTO` (repeatable) lets an operator declare a known-good
  engineering-command pair (e.g. an EWS writing to a PLC rack) so repeat
  captures don't flag the same expected pair High/Critical forever. SRC/DST
  may be an IP or CIDR; PROTO is `modbus`, `cip`, `s7`, `dnp3`, or `any`.
  Declared pairs are excluded from `ics.modbus_writes` /
  `ics.cip_engineering` / `ics.s7_engineering` / `ics.dnp3_engineering` and
  rolled up instead into a new Info-severity `ics.trusted_writer_activity`
  finding — an unverified operator assertion, not proof of authentication.
  A finding mixing trusted and untrusted pairs keeps its original severity
  for the untrusted pairs only, so one declared pair can't mask an
  unexpected writer sharing the same protocol. The `--ai` audit log records
  a count + SHA-256 digest of the declared rules, never the raw
  CIDRs/addresses. A declaration matching no traffic in the capture warns
  on stderr. Rule catalog now lists **24** rules.
- **New workspace crate `crates/otsniff-privacy`** (ADR-0016): the pseudonym
  scrub/unscrub mechanics and the fail-closed leak detector, extracted so a
  planned companion tool ("otsniff-hunt") can reuse the same
  never-see-real-identifiers guarantee over data otsniff itself never
  touches, without forking or duplicating the verified privacy core.

### Changed

- **Internal refactor:** moved the pseudonym scrub/unscrub mechanics and
  the fail-closed leak detector into the new `crates/otsniff-privacy`
  (ADR-0016). `ScrubMap`, `scrub_text`/`unscrub_text`, `pseudonym_regex`,
  and `leak_detector::{scan, ensure_clean, ensure_no_map_values}` moved out
  of `src/scrub.rs` and `src/ai/leak_detector.rs` along with their Kani
  proofs and unit tests — not verbatim: return types now use the new
  crate's own `PrivacyError` instead of `OtError`, and
  `is_canonical_pseudonym`, `max_index`, `merge_family`, and
  `pseudonym_regex` widened from private to `pub` (and
  `parse_pseudonym_index` from private to `pub(crate)`) so otsniff's call
  sites (and a future otsniff-hunt) can reach them across the crate
  boundary. `otsniff`'s own `src/scrub.rs` keeps
  only the population functions (`build_map`, `build_map_at`, `merge_map`)
  that walk otsniff's `Observations` capture model.
  - No user-facing or CLI behavior change for all existing fixtures and
    smoke tests: `otsniff analyze`, `scrub`, `unscrub`, and `diff` all
    produce byte-identical output to before this change. (See the
    `### Fixed` entry below for one deliberate, narrow exception uncovered
    by a later review cycle.)
  - `OtError::PrivacyLeak { kind, message }` is now
    `OtError::Privacy(otsniff_privacy::PrivacyError)`, following the same
    wrapping shape as the existing `OtError::Segmentation` variant (an
    `OtError` variant wrapping the sub-crate's own error type), for the
    fail-closed leak-detector trip specifically. Unlike `Segmentation`,
    which derives `#[from]`, `Privacy` uses a hand-written `From` impl —
    `#[from]` also derives `#[source]`, which would have added a new
    `caused by: ...` stderr line (main.rs walks `Error::source()`) that
    didn't exist pre-extraction, violating the "no observable behavior
    change" constraint. The error message shape
    (`"privacy invariant tripped: ..."`) and exit code (75) are unchanged
    for that path. See ADR-0016's "Decision refinement" section.
  - `ScrubMap::validate()` / `merge_family()`'s structural map-corruption
    errors (empty pseudonym, empty real value, non-canonical pseudonym,
    duplicate real value, pseudonym collision, or an exhausted `u32`
    pseudonym index space in `merge_family`) are a distinct
    `otsniff_privacy::PrivacyError::MapCorrupt` variant, routed back to
    `OtError::Parse` by that same hand-written `From` impl — preserving the
    pre-extraction exit code (70) and `"pcap parse error: ..."` message
    prefix for that class of error exactly, rather than folding it into the
    75/"privacy invariant tripped" shape above — except the `u32`-exhaustion
    cause, which is new hardening with no pre-extraction `OtError::Parse`
    precedent (see `### Fixed` below).

### Fixed

- `otsniff scrub --baseline-map` (and other baseline-map-consuming paths)
  no longer panics (debug) or silently mints a colliding
  `host_000`/`mac_000`/`name_000` pseudonym (release) when a baseline
  map's family already contains a `u32::MAX`-indexed key; it now fails
  cleanly with exit code 70.
