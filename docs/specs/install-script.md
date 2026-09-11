# Install script

## Problem

The current install path is "go to the GitHub releases page, pick the
right tarball for your OS/arch, download it, verify the SHA, extract
it, move the binary to PATH, strip macOS quarantine if relevant." Eight
steps for what should be one. Comparable Rust CLIs (rustup, jira-cli,
gh) all ship a `curl ... | sh` one-liner; otsniff should too.

## Decision

Ship `install.sh` at the repo root. Users run:

```sh
curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh
```

Script behavior:

- Detects OS (Linux / macOS) and arch (x86_64 / aarch64)
- Maps to the right release tarball name
- Looks up the latest stable release tag via the GitHub API (or honors
  `OTSNIFF_VERSION` env var)
- Downloads tarball + sha256 sidecar, verifies the checksum
- Extracts to a tmp dir, moves the binary to `$OTSNIFF_INSTALL_DIR`
  (default `~/.local/bin`), `chmod 0755`
- Strips macOS Gatekeeper quarantine (binary isn't notarized)
- Verifies the binary runs (`--version` succeeds)
- Repeats download/verify/extract/run-verify for each pack requested via
  `--packs` or `OTSNIFF_PACKS` (ADR-0019), installing each as
  `otsniff-<pack>` in the same directory
- Warns if the install dir isn't on PATH and prints the exact line to
  add to the user's shell profile

### Packs (ADR-0019)

`install.sh [VERSION] [--packs a,b,c]`. Pack artifacts are named and laid
out identically to the core (`otsniff-<pack>-<tag>-<target>.tar.gz`
containing `<stem>/otsniff-<pack>`), so one `install_artifact()` covers
both.

- Pack names are shape-checked (`[A-Za-z0-9_-]+`) before becoming a
  filename or URL, but **not** checked against a catalog — the installer
  has none. An unknown-but-well-formed name surfaces as a download
  failure naming the artifact it looked for.
- **A failing pack does not fail the core install.** The core is already
  on disk and working by then, so a pack failure is a warning, the
  success banner still prints (with a `FAILED:` line naming the pack and
  the `otsniff pack add` retry), and the script exits non-zero so
  automation still sees the partial failure (ADV-P1 F-P1-020).
- Each pack is run-verified (`--help` succeeds) to the same standard as
  the core, so a pack that installs but can't execute is caught here
  rather than on first use.

### Checksum verification

Compares digests directly: parse the first field of the sidecar, require
exactly 64 hex characters, compute the tarball's own digest, compare.

It deliberately does **not** use `sha256sum -c`. That is fail-open on
macOS — Darwin's `/sbin/sha256sum` exits 0 for a checklist containing no
properly formatted lines, so an empty or HTML sidecar body would "verify"
(ADV-P1 F-P1-001). Computing the digest of one named file is safe on every
implementation; only the `-c` decision was not.

`tar` is invoked with `--no-same-owner --no-same-permissions`, and the
installed mode is set with an absolute `chmod 0755` rather than `chmod +x`
— `+x` only *adds* bits, so a substituted archive member with mode `04755`
would otherwise land setuid under the documented sudo install
(ADV-P1 F-P1-005).

## Scope

**In scope:**

- Linux x86_64 (the only Linux target we ship today)
- macOS x86_64 + aarch64
- POSIX shell only (`#!/usr/bin/env sh`, no bash-isms) so it runs on
  systems with `dash` as `/bin/sh`
- Honors env vars: `OTSNIFF_VERSION` (pin a version), `OTSNIFF_INSTALL_DIR`
  (override install location), `OTSNIFF_PACKS` (comma-separated packs)
- Either `sha256sum` (Linux) or `shasum -a 256` (macOS) to *compute* the
  digest; the comparison is done by the script, not by the tool

**Not in scope:**

- Windows (curl-pipe-sh isn't the Windows install pattern; we'll add a
  PowerShell installer when there's demand)
- Linux aarch64 (we don't ship that target yet — see ROADMAP item to
  re-add it once cross-rs glibc story is resolved)
- Sudo/system-wide installs — script always uses user-level
  `~/.local/bin`. Users wanting system install can `sudo mv` after.
- Updating an existing install — the script overwrites if the binary
  is already there. Idempotent for re-runs of the same version.

## Failure modes

The script must exit non-zero with a clear message when:

- OS or arch isn't supported (e.g., user on Linux aarch64 today)
- The version tarball doesn't exist on the release page
- Checksum verification fails
- The binary fails to run after install (e.g., wrong arch downloaded
  somehow, dynamic linker issue)

It must NOT:

- Modify the user's shell profile automatically. Print the line, let
  them paste it. Auto-modifying ~/.zshrc is rude.
- Require sudo. If the user wants system install they can do that
  themselves.
- Skip the checksum check silently. If both `sha256sum` and `shasum`
  are missing, abort.

## Test plan

The script can't be properly tested in CI without a release fixture,
but should be exercised manually before announcing:

- macOS arm64 (current dev machine): `curl ... | sh` succeeds
- macOS x86_64: same via Rosetta or an Intel Mac
- Linux x86_64: in a Docker container `docker run --rm -it ubuntu:24.04
  bash -c "apt-get update && apt-get install -y curl ca-certificates &&
  curl ... | sh"`
- Bad version: `OTSNIFF_VERSION=v99.0.0 curl ... | sh` should fail with
  a clear error
- Tampered checksum: substitute a wrong sha256, verify abort

## Touched files

- `install.sh` (new, ~120 lines)
- `README.md` (add the curl one-liner near the top of Install section)
