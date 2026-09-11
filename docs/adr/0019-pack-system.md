# ADR-0019: Packs — optional components installed alongside the core binary

## Status
Accepted — implemented.

## Context

otsniff ships as one static binary and `install.sh` drops exactly that
binary into `~/.local/bin`. That's the whole install story, and it's a good
one for the core tool. But the project now has components that not every
operator wants: `otsniff-web` (ADR-0018) is a separate binary with its own
`axum`/`tokio` dependency tree, "otsniff-hunt" is planned (ADR-0016), and
P1-8 (IOC matching against curated threat-intel) is blocked partly on
*where curated data would live* — it obviously shouldn't be compiled into
the core binary on a release cadence tied to code changes.

The ask: `install.sh` gives you the core, and you add pieces afterward.

## Decision

**A pack is a separately-distributed binary named `otsniff-<name>`,
installed next to the core binary.** Four parts:

### D1 — Packs are separate binaries, not Cargo features

Rejected: compile-time feature packs (`cargo install otsniff --features
web`). They cannot satisfy the actual ask — you can't *add a piece after
installing* without rebuilding from source, and the primary install path
is a prebuilt binary from a GitHub release. Publishing one prebuilt
artifact per feature combination is a combinatorial non-starter.

A pack being its own binary also means a pack can carry dependencies the
core refuses (`otsniff-web` already does) without any of it reaching
someone who only installs the core.

### D2 — Git-style dispatch: `otsniff <pack>` → `otsniff-<pack>`

`otsniff web --port 7878` execs the `otsniff-web` binary with the
remaining arguments, the same way `git foo` finds `git-foo`. The core's
clap `Command` enum gains an `#[command(external_subcommand)]` variant;
anything that isn't a built-in subcommand is resolved as a pack.

**Resolution order: the directory containing the running `otsniff`
binary first, then `PATH`.** Sibling-first is deliberate — `install.sh`
puts core and packs in the same directory, so the common case never
consults `PATH`, and a writable-but-unrelated `PATH` entry can't shadow
an installed pack. (Dispatching to a `PATH`-resolved binary is the same
code-execution surface `git`, `kubectl`, and `gh` accept for plugins; the
sibling-first ordering narrows it.)

Unknown names produce an error naming the pack and pointing at
`otsniff pack list` — not clap's generic "unrecognized subcommand", which
would be a worse message now that unknown subcommands are a meaningful
category.

Dispatch resolves *any* `otsniff-<name>` binary, not only catalog
entries — again matching git, where any `git-foo` on `PATH` is a
subcommand. The catalog (D4) governs what `pack list` advertises and what
`pack add` can fetch; it is deliberately not a gate on execution, so a
third party can ship an `otsniff-` binary without needing a core release
to bless it.

### D3 — `pack add` downloads + verifies; it does not pipe a remote script to a shell

`otsniff pack add web` constructs the release URL itself, downloads the
tarball and its `.sha256` sidecar via `curl`, verifies the checksum with
`sha256sum`/`shasum`, extracts with `tar`, and places the binary next to
the running `otsniff`. It shells out to tools the user already has —
consistent with ADR-0007's "shell out to installed tooling rather than
embed an HTTP client/SDK", and with ADR-0001's aversion to dependency
weight in the core.

It deliberately does **not** run `curl … | sh` of a remote script from
inside the binary: no downloaded shell code is ever executed, and a failed
checksum aborts before anything is placed. That this duplicates ~40 lines
of `install.sh`'s logic is an accepted cost — the alternative is a tool
that executes remote scripts on the user's behalf.

`pack remove` deletes the sibling binary and nothing else. Packs own no
state outside their own data directories (`otsniff-web` has
`--data-dir`), so removal never touches user data.

### D4 — The registry is a static list in the core binary

`otsniff pack list` works offline: it prints the known packs and checks
which are installed by resolving `otsniff-<name>` the same way dispatch
does. No network, no manifest fetch, no HTTP client.

The trade-off: adding a pack to the catalog requires a core release. That
is the right trade for a handful of first-party packs, and it keeps `pack
list` honest — it can only advertise packs whose artifacts a matching core
release actually publishes. A remote manifest would decouple them at the
cost of a network dependency in the one command that should always work.

## Consequences

**We accept** that the registry starts with exactly one pack (`web`).
The mechanism is the deliverable; the catalog grows as
`otsniff-hunt` (ADR-0016) and data packs land. Advertising packs that
can't be installed yet would be worse than a short list.

**We accept** that `pack add` requires `curl` and `tar` on the box — the
same tools `install.sh` already requires, on the same install path.

**We gain** a distribution answer for P1-8 (IOC matching against curated
OT threat-intel): a data pack can version and ship on its own cadence
without bloating the core binary or tying feed updates to code releases.
That doesn't resolve P1-8's sourcing/licensing question, but it removes
the "where would this even live" half of it.

**Windows** gets `pack list`/dispatch but `pack add` is unsupported there
for now (the extract/verify path assumes a POSIX shell environment);
Windows users install pack binaries from the release page manually. The
error message says so rather than failing obscurely.

## Alternatives considered

**A single fat binary with runtime feature flags.** Rejected: it makes
everyone pay `otsniff-web`'s dependency tree (axum, tokio, hyper) to get
a PCAP triage CLI, which is precisely what ADR-0018's crate boundary
exists to prevent.

**Dynamically loaded plugins (`.so`/`.dylib`).** Rejected: Rust has no
stable ABI, so plugins would have to be built against the exact compiler
and crate versions as the host. Separate processes over a documented CLI
contract is the boring, robust option — and the one git/kubectl/gh all
converged on.
