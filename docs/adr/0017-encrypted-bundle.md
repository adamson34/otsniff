# ADR-0017: Encrypted report bundle (`bundle`/`unbundle`)

## Status
Accepted — implemented (P2-7). `src/bundle.rs`, `otsniff bundle`/`otsniff
unbundle`.

## Context

otsniff's BCSI handling commitment (NERC CIP-011 alignment, `docs/audits/
scrub-audit-cip011.md`) is, for data at rest, currently a documentation
claim: the tool *says* the scrub map (`--map`) and privacy audit log are
sensitive and should be protected at rest, and relies on the operator to
encrypt the directory, use disk encryption, or otherwise handle it
themselves. Nothing in otsniff itself closes that window between `scrub`
(or `analyze --ai`, which writes `report.audit.json` automatically) and
whenever the operator gets around to protecting the output.

## Decision

Add a paired `bundle` / `unbundle` subcommand that encrypts `<stem>.html` +
`<stem>.map.json` + `<stem>.audit.json` (whichever exist) into one file,
and reverses it. Four sub-decisions:

### D1 — `age` (scrypt passphrase mode) for the encryption primitive

Rejected rolling our own: symmetric encryption is exactly the kind of code
where "small and simple" is the wrong instinct — key derivation, nonce
handling, and authenticated-encryption framing are easy to get subtly wrong
and hard to notice you got wrong. `age` (the `str4d/rage` implementation,
MIT/Apache-2.0, MSRV 1.74) is the modern, widely-audited choice the
roadmap named. `age::Encryptor::with_user_passphrase` / `age::Decryptor`
+ `age::scrypt::Identity` cover exactly the "one passphrase, one file"
shape `bundle` needs with no extra features (`cli-common` — interactive
prompting — was considered and deferred; see D2).

### D2 — Passphrase via `--passphrase-env VAR`, never a bare CLI argument

The roadmap sketch showed `--passphrase` as a flag. Rejected: a passphrase
passed as a literal CLI argument is visible in shell history and to every
other process on the box via `ps`/`/proc/<pid>/cmdline` for as long as the
process runs — exactly the kind of at-rest-adjacent leak this feature
exists to close. `--passphrase-env VAR` reads the passphrase from a named
environment variable instead, which is still not perfect (env vars are
visible to child processes and some `/proc` inspection) but is the
standard, expected trade-off for secret-bearing CLI tools and is scriptable
without an interactive prompt.

**Deferred: interactive prompting.** `age`'s `cli-common` feature bundles
`rpassword`/`pinentry`/`console`/`is-terminal` for no-echo terminal
prompting, which would be a nicer default UX for a human running `bundle`
by hand. Deferred to keep the dependency footprint to just `age` itself
(ADR-0001's "no heavy deps unless load-bearing" — `bundle` is scriptable
without it, and adding it later is a pure addition, not a breaking change).

### D3 — A minimal custom container format, not a real ZIP

The roadmap's "zips ... into one file" is casual phrasing, not a
compatibility requirement — `bundle` and `unbundle` are always used as a
pair by otsniff itself; nothing needs to open the *plaintext* container
with an unrelated ZIP tool (the outer file is `age`-encrypted regardless,
so a real ZIP wouldn't be more inspectable anyway). Format: an 8-byte
magic, a `u32` entry count, then per entry a `u16` name length + name +
`u64` content length + content, all little-endian. Adding a `zip`/`tar`
dependency for a two-command, otsniff-internal pairing would be exactly
the kind of unneeded-compatibility weight ADR-0001 already rejects for
PCAP parsing.

### D4 — Fail-closed extraction: reject any non-bare-filename entry name

The bundle's plaintext is attacker-controlled the moment anyone else can
produce a file that decrypts under a guessed or shared passphrase (a weak
passphrase, or one an operator reused). `unbundle` refuses to extract any
entry whose stored name contains a path separator or is `.`/`..`, so a
crafted bundle cannot write outside the requested output directory.
`bundle` itself never emits such a name (its three entries are always
literal `"report.html"` / `"map.json"` / `"audit.json"`); the check exists
for the input side of `unbundle`, not the output side of `bundle`.

## Consequences

**We accept** a meaningfully larger dependency tree (`age` pulls in
`x25519-dalek`, `chacha20poly1305`, `scrypt`, and — for its own localized
error messages — `fluent`/`i18n-embed`). This is the cost of using an
audited encryption implementation instead of hand-rolling one; `cargo deny
check` passes against it (licenses/advisories/bans all clear) as of this
writing.

**We accept** that `bundle`'s stem-based file discovery is a convention,
not a contract: it looks for `<stem>.html` / `<stem>.map.json` /
`<stem>.audit.json` specifically (mirroring `analyze`'s own
`<output>.audit.json` derivation from ADR-0012), so a `--map` file saved
under a different name won't be picked up automatically. Missing files are
skipped, not an error — a non-`--ai` report (no map, no audit log) still
bundles its `.html` alone.

**This does not change the privacy invariant.** `bundle`/`unbundle` operate
entirely after the scrub → AI → unscrub round trip has already happened;
the AI still never sees real values regardless of whether the operator
bundles the output afterward.

## Alternatives considered

**A symmetric-cipher crate lower-level than `age`** (e.g. hand-rolling
ChaCha20-Poly1305 + a KDF directly via RustCrypto crates). Rejected: `age`
already composes those primitives correctly (nonce/salt handling, format
versioning) and is the roadmap's own stated preference; reimplementing
that composition ourselves reintroduces exactly the risk D1 rejects.

**`cocoon`** (the roadmap's named alternative). Rejected in favor of `age`
for the same "modern choice, small footprint, audited" reasoning the
roadmap itself gave `age` — `cocoon` is a smaller, less-audited project by
comparison.
