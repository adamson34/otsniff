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
  (default `~/.local/bin`)
- Strips macOS Gatekeeper quarantine (binary isn't notarized)
- Verifies the binary runs (`--version` succeeds)
- Warns if the install dir isn't on PATH and prints the exact line to
  add to the user's shell profile

## Scope

**In scope:**

- Linux x86_64 (the only Linux target we ship today)
- macOS x86_64 + aarch64
- POSIX shell only (`#!/usr/bin/env sh`, no bash-isms) so it runs on
  systems with `dash` as `/bin/sh`
- Honors env vars: `OTSNIFF_VERSION` (pin a version), `OTSNIFF_INSTALL_DIR`
  (override install location)
- Both `sha256sum` (Linux) and `shasum -a 256` (macOS) for verification

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
