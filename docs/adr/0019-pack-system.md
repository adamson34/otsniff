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

**Resolution order: `OTSNIFF_INSTALL_DIR` if set, then the directory
containing the running `otsniff` binary, then `PATH`.** Install-location-first
is deliberate — `install.sh` puts core and packs in the same directory, so
the common case never consults `PATH`, and a writable-but-unrelated `PATH`
entry can't shadow an installed pack.

Two honest limits on that (ADV-P1 F-P1-002, F-P1-004):

- It narrows *shadowing*, not the general surface. Dispatching to a
  `PATH`-resolved binary is the same code-execution surface `git`,
  `kubectl`, and `gh` accept for plugins, and the default install dir
  (`~/.local/bin`) is user-writable by definition — anyone who can write
  there already has code execution by other means.
- `PATH` entries are filtered to **absolute** paths. `split_paths`
  preserves empty components, and an empty or relative entry resolves
  against the process CWD, so `PATH="/usr/bin:"` would have made
  `otsniff <name>` execute a planted `./otsniff-<name>` — and this tool's
  usage pattern is "operator cd's into a directory of captures."

Pack names are also validated (`[A-Za-z0-9_-]+`) before being
interpolated into a filename, since dispatch takes the name from argv and
the result is joined onto a search directory and `exec`d.

Unknown names produce an error naming the pack and pointing at
`otsniff pack list`, distinguishing "known pack, not installed" from "no
such thing" — a distinction clap's external-subcommand handling cannot
make, since by then every unknown name looks alike.

**Correction (ADV-P1 F-P1-010).** This ADR originally justified that by
calling clap's own message "generic". That was wrong: clap 4 emits
`tip: a similar subcommand exists: 'analyze'`, and adding
`external_subcommand` made that path unreachable — so a one-letter typo
of a built-in (`analyse`) lost its suggestion. The suggestion is now
reimplemented here (edit distance ≤ 2 over built-in subcommand *and* pack
names), with a test asserting the hand-maintained subcommand list matches
what clap actually accepts.

Dispatch resolves *any* `otsniff-<name>` binary, not only catalog
entries — again matching git, where any `git-foo` on `PATH` is a
subcommand. The catalog (D4) governs what `pack list` advertises and what
`pack add` can fetch; it is deliberately not a gate on execution, so a
third party can ship an `otsniff-` binary without needing a core release
to bless it.

### D3 — `pack add` downloads + verifies; it does not pipe a remote script to a shell

`otsniff pack add web` constructs the release URL itself, downloads the
tarball and its `.sha256` sidecar via `curl`, extracts with `tar`, and
places the binary in the install directory. Transport shells out to tools
the user already has — consistent with ADR-0007's "shell out to installed
tooling rather than embed an HTTP client/SDK", and with ADR-0001's
aversion to dependency weight in the core.

It deliberately does **not** run `curl … | sh` of a remote script from
inside the binary: no downloaded shell code is ever executed, and a failed
checksum aborts before anything is placed. That this duplicates ~40 lines
of `install.sh`'s logic is an accepted cost — the alternative is a tool
that executes remote scripts on the user's behalf. (ADV-P1 found that the
two copies had already diverged on security-relevant lines in *both*
directions; see Consequences.)

**Checksum verification is done in-process, not delegated (ADV-P1
F-P1-001).** The first implementation handed the downloaded sidecar to
`sha256sum -c` and trusted its exit status. That is fail-open on macOS:
Darwin's `/sbin/sha256sum` exits 0 for a checklist containing no properly
formatted lines, so an empty or HTML sidecar body "verified" — and
`which` finds it before the fail-closed `shasum` fallback on a default
macOS `PATH`. Both copies now parse the expected digest out of the
sidecar, compute the tarball's digest themselves, and compare: `sha2` is
already a dependency of the core crate, so the Rust path needs no external
checksum tool at all. Fail-closed by construction — a missing, empty, or
non-checksum sidecar cannot produce a passing comparison.

Note what the checksum does and does not buy: the sidecar ships from the
same release as the tarball, so it protects against a corrupted or
substituted *download*, not against a malicious *release*. Signing
(minisign/cosign) is the answer to the latter and is not implemented here
or in `install.sh`.

Installation is staged then renamed, so a failure mid-copy can't leave a
truncated binary that `pack list` reports as installed, and a symlink at
the destination is replaced rather than written through.

`pack remove` deletes the binary **in the install directory** and nothing
else. If a copy exists elsewhere on `PATH` it reports the path and
refuses, since otsniff didn't install it — deleting it could corrupt a
package manager's manifest (ADV-P1 F-P1-003). Packs own no state outside
their own data directories (`otsniff-web` has `--data-dir`), so removal
never touches user data.

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
same tools `install.sh` already requires, on the same install path. It no
longer requires a checksum tool (see D3).

**The two copies of the install logic are a live hazard, not a
theoretical one.** ADV-P1 found they had already diverged in both
directions within a single PR: the shell copy guarded aarch64-Linux and
used `mktemp -d`; the Rust copy cleared setuid and failed closed on a
missing checksum tool. Neither was a superset of the other, and the same
fail-open checksum bug existed in both. They have been reconciled, but
nothing structurally prevents the next divergence — the honest options are
to keep them in deliberate lockstep with paired tests, or to have
`install.sh` bootstrap only the core and let `otsniff pack add` be the
sole pack installer. That consolidation is not done here.

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
