#!/usr/bin/env sh
#
# otsniff installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh
#
#   # Pin a specific version:
#   curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh -s -- v0.2.0
#
#   # Install optional packs alongside the core binary (ADR-0019):
#   curl -fsSL https://raw.githubusercontent.com/adamson34/otsniff/main/install.sh | sh -s -- --packs web
#
# Env vars (alternate ways to override):
#   OTSNIFF_VERSION       Pin a specific tag (also takes the first positional arg).
#   OTSNIFF_INSTALL_DIR   Where to put the binaries (default: $HOME/.local/bin).
#   OTSNIFF_PACKS         Comma-separated packs (also takes --packs).
#
# What this does:
#   1. Detect OS/arch and pick the matching release tarball.
#   2. Download tarball + .sha256 sidecar from the GitHub release.
#   3. Verify the checksum.
#   4. Extract, move the binary to the install dir, strip macOS quarantine.
#   5. Repeat 2-4 for each requested pack (installed as otsniff-<pack>).
#   6. Confirm the binary runs and warn if the install dir isn't on PATH.
#
# What this does NOT do:
#   - Modify your shell profile automatically (it prints the line for you).
#   - Use sudo or install system-wide. Do that yourself if you want it.
#   - Skip checksum verification. Aborts if no sha256 tool is available.

set -eu

# ADV-P2 F-P2-039: `mkdir -p "$INSTALL_DIR"` inherits the caller's umask, so
# `umask 000` plus the documented `sudo` install created /usr/local/bin mode
# 0777. Nothing this script writes should ever be group- or world-writable.
umask 022

REPO="adamson34/otsniff"
BIN_NAME="otsniff"

err() { echo "otsniff-install: $*" >&2; exit 1; }
warn() { echo "otsniff-install: WARNING: $*" >&2; }
info() { echo "otsniff-install: $*"; }

# ADV-P2 F-P2-040: `set -u` turns an unset $HOME into a raw
# `HOME: unbound variable` with no hint about the fix. Containers and CI
# runners routinely have no HOME.
# `${VAR+set}` rather than `${VAR:-}`: an *empty* OTSNIFF_INSTALL_DIR must
# reach the absolute-path check below and be refused, not silently fall back
# to the default. The Rust copy sees `Some("")` from `var_os` and rejects it
# for the same reason; falling back here would be a fresh divergence of
# exactly the kind F-P2-005 was about.
if [ -n "${OTSNIFF_INSTALL_DIR+set}" ]; then
    INSTALL_DIR="$OTSNIFF_INSTALL_DIR"
elif [ -n "${HOME:-}" ]; then
    INSTALL_DIR="$HOME/.local/bin"
else
    err "HOME is not set, so there is no default install directory. Set OTSNIFF_INSTALL_DIR=/absolute/path and retry."
fi

# ADV-P2 F-P2-005: the Rust copy rejects a non-absolute OTSNIFF_INSTALL_DIR
# because the write path and the search path would then disagree — `pack add`
# installs to ./otsniff-web and reports success while `pack list` says "not
# installed", and `pack remove` deletes from whatever directory the operator
# happens to be in. Same value, same env var, same rule here.
case "$INSTALL_DIR" in
    /*) ;;
    *) err "OTSNIFF_INSTALL_DIR must be an absolute path (got '$INSTALL_DIR') — a relative install directory resolves against the current directory, which is exactly what otsniff refuses to search." ;;
esac

# ── Parse args ──────────────────────────────────────────────────
# Positional arg is the version (kept for backwards compatibility);
# --packs takes a comma-separated list. Names are shape-checked below (they
# become filenames and URLs) but not checked against a catalog — the
# installer has none, so an unknown-but-well-formed name surfaces as a
# download failure naming the artifact it looked for.
VERSION="${OTSNIFF_VERSION:-}"
PACKS="${OTSNIFF_PACKS:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --packs)
            [ $# -ge 2 ] || err "--packs needs a value, e.g. --packs web"
            PACKS="$2"
            shift 2
            ;;
        --packs=*)
            PACKS="${1#--packs=}"
            shift
            ;;
        -h|--help)
            # Inlined rather than read from $0: piped through `curl | sh`
            # there is no script file to read.
            cat <<'USAGE'
otsniff installer.

  install.sh [VERSION] [--packs LIST]

  VERSION        Release tag to install (default: latest), e.g. v0.6.0
  --packs LIST   Comma-separated optional packs, e.g. --packs web

Env: OTSNIFF_VERSION, OTSNIFF_PACKS, OTSNIFF_INSTALL_DIR (default ~/.local/bin)

Packs can also be added later with: otsniff pack add <name>
USAGE
            exit 0
            ;;
        -*)
            err "unknown option: $1 (supported: --packs <list>)"
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

# ADV-P2 F-P2-002: VERSION reaches the download URL from three untrusted-ish
# sources (env var, positional arg, API scrape). curl performs RFC 3986
# dot-segment removal, so a value containing `../` escapes the repo path
# entirely — and the attacker then supplies both the tarball and its sidecar,
# so checksum verification passes and the binary is executed below. Mirrors
# release_tag()'s charset check in the Rust copy.
validate_version() {
    case "$1" in
        "" ) err "empty version. Set OTSNIFF_VERSION=vX.Y.Z and retry." ;;
        *[!A-Za-z0-9.+-]* )
            err "refusing version '$1': expected something like v0.7.0 (letters, digits, '.', '+', '-' only)." ;;
    esac
}
[ -z "$VERSION" ] || validate_version "$VERSION"

# ── Detect OS ───────────────────────────────────────────────────
case "$(uname -s)" in
    Linux*)   OS=unknown-linux-gnu ;;
    Darwin*)  OS=apple-darwin ;;
    *)        err "unsupported OS: $(uname -s). See https://github.com/$REPO/releases for manual install." ;;
esac

# ── Detect arch ─────────────────────────────────────────────────
case "$(uname -m)" in
    x86_64|amd64)    ARCH=x86_64 ;;
    arm64|aarch64)   ARCH=aarch64 ;;
    *)               err "unsupported architecture: $(uname -m)." ;;
esac

# Linux ships only x86_64 today.
if [ "$OS" = "unknown-linux-gnu" ] && [ "$ARCH" != "x86_64" ]; then
    err "$ARCH-$OS isn't released yet. See https://github.com/$REPO/releases or build from source."
fi

TARGET="$ARCH-$OS"

# ── Download helper ─────────────────────────────────────────────
# ADV-P2 F-P2-011: the ADV-P1 curl hardening landed in the Rust copy only,
# leaving the *more* exposed copy — this one, delivered via `curl | sh` —
# on a bare `-fsSL`. `-L` with curl's default --proto-redir permits an
# https→http downgrade on redirect, and nothing bounded the response size.
# `--` terminates option parsing so a URL or path can never be read as a flag
# (F-P2-048). Kept as a function so there is one copy to audit.
#   $1 url, $2 destination file, $3 "quiet" to suppress the progress meter.
fetch() {
    _fetch_flags="-fSL"
    [ "${3:-}" != "quiet" ] || _fetch_flags="-fsSL"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 20 --max-time 300 --retry 2 \
        --max-redirs 5 --max-filesize 268435456 \
        "$_fetch_flags" -o "$2" -- "$1"
}

# ── Pick version ────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
    info "looking up latest release..."
    # ADV-P2 F-P2-009: `/releases/latest` excludes drafts *and* prereleases.
    # The published stable release is the right first answer and normally
    # resolves fine — but there are two gaps, and this used to fail with
    # nothing to suggest but pinning a version by hand:
    #   1. A repo with no stable release at all (only vX.Y.Z-dev.N
    #      prereleases) has no `latest` whatsoever.
    #   2. Between tagging a stable release and a human publishing its draft
    #      (release.yml keeps that gate deliberately — see #106), `latest`
    #      still points at the previous stable.
    # So fall back to the full release list, which includes prereleases, and
    # take the newest published entry.
    _rel=$(mktemp 2>/dev/null || mktemp /tmp/otsniff-rel.XXXXXXXXXX 2>/dev/null) \
        || err "could not create a temporary file (tried \$TMPDIR and /tmp). Set TMPDIR to a writable directory and retry."
    VERSION=""
    if fetch "https://api.github.com/repos/$REPO/releases/latest" "$_rel" quiet 2>/dev/null; then
        VERSION=$(grep '"tag_name"' "$_rel" | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    fi
    if [ -z "$VERSION" ] \
        && fetch "https://api.github.com/repos/$REPO/releases?per_page=20" "$_rel" quiet 2>/dev/null; then
        # The API returns newest-first. Drafts have no downloadable assets at
        # a stable URL, so skip them; prereleases are installable.
        VERSION=$(tr ',' '\n' < "$_rel" \
            | grep -E '"(tag_name|draft)"' \
            | sed 's/^ *//' \
            | awk -F'"' '
                /"draft"/  { skip = ($0 ~ /true/); next }
                /"tag_name"/ { if (!skip) { print $4; exit } }' )
    fi
    rm -f "$_rel"
    [ -n "$VERSION" ] || err "could not determine latest release. Set OTSNIFF_VERSION=vX.Y.Z and retry.
  Released versions: https://github.com/$REPO/releases"
    # The scrape is unauthenticated text from the network — validate it too.
    validate_version "$VERSION"
    info "latest release is $VERSION"
fi

# ── Stage in temp dir ───────────────────────────────────────────
# The fallback used to be `mktemp -d -t 'otsniff-install'`, which is a
# BSD-ism: on macOS `-t` takes a *prefix*, but GNU coreutils requires a
# template with at least three X's and fails with
# `mktemp: too few X's in template`. So on Linux — the majority install
# target — the fallback was dead, and any first-attempt failure (an unset,
# unwritable, or nonexistent $TMPDIR) aborted with that message instead of
# something actionable. An explicit template works on both.
TMP=$(mktemp -d 2>/dev/null || mktemp -d /tmp/otsniff-install.XXXXXXXXXX 2>/dev/null) \
    || err "could not create a temporary directory (tried \$TMPDIR and /tmp). Set TMPDIR to a writable directory and retry."
# ADV-P2 F-P2-038: a POSIX trap handler that does not itself exit returns
# control to the interrupted point — so Ctrl-C deleted $TMP and the script
# then carried on against a directory that no longer existed. Only the EXIT
# handler may fall through.
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# ── Install one release artifact ────────────────────────────────
# $1 is the binary/artifact base name: "otsniff" for the core, or
# "otsniff-<pack>" for a pack. Both are packaged identically —
# <base>-<version>-<target>.tar.gz containing a directory of that name
# with the binary inside — so one function covers both.
install_artifact() {
    _base="$1"
    _stem="${_base}-${VERSION}-${TARGET}"
    _tarball="${_stem}.tar.gz"
    _url="https://github.com/$REPO/releases/download/${VERSION}/${_tarball}"

    info "downloading ${_tarball}..."
    # ADV-P2 F-P2-012: curl's own stderr is the only thing that distinguishes
    # "no such release" from a TLS failure, a proxy blocking the connection,
    # or a timeout. It used to be sent to /dev/null and every one of those
    # reported as a wrong version. Let it through.
    if ! fetch "$_url" "$TMP/$_tarball"; then
        err "download failed: $_url
  curl's error is above. If it is a 404, check that $VERSION publishes this
  artifact at https://github.com/$REPO/releases; otherwise it is a network,
  proxy, or TLS problem on this machine."
    fi
    fetch "${_url}.sha256" "$TMP/${_tarball}.sha256" quiet \
        || err "checksum sidecar download failed for ${_tarball} (see curl's error above)."

    info "verifying ${_tarball}..."
    # Compare digests ourselves rather than handing the sidecar to
    # `sha256sum -c`: Darwin's /sbin/sha256sum exits 0 for a checklist with
    # no properly formatted lines, so an empty or HTML sidecar body would
    # "verify" (ADV-P1 F-P1-001). Computing the hash of one named file is
    # safe on every implementation; it was only the -c decision that wasn't.
    _expected=$(awk 'NR==1 {print $1}' "$TMP/${_tarball}.sha256" 2>/dev/null || true)
    if [ "${#_expected}" -ne 64 ] || [ -n "$(printf '%s' "$_expected" | tr -d '0-9a-fA-F')" ]; then
        err "the checksum sidecar for ${_tarball} does not contain a SHA-256 digest — refusing to install.
  The download may have been intercepted, or the release may be malformed."
    fi
    # ADV-P2 F-P2-022: neither copy checked the sidecar's *filename* field, so
    # a sidecar naming a different artifact — the wrong pack, the wrong
    # target, the wrong version — was accepted as long as its digest happened
    # to match. Sidecars are generated as `sha256sum <stem>.tar.gz`, so the
    # field is the bare basename. Rust's expected_digest() does the same.
    _named=$(awk 'NR==1 {sub(/^[*]/, "", $2); print $2}' "$TMP/${_tarball}.sha256" 2>/dev/null || true)
    if [ -n "$_named" ] && [ "${_named##*/}" != "$_tarball" ]; then
        err "the checksum sidecar for ${_tarball} names a different file ('${_named}') — refusing to install.
  The release may be malformed, or the sidecar may have been substituted."
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        _actual=$(sha256sum "$TMP/$_tarball" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        _actual=$(shasum -a 256 "$TMP/$_tarball" | awk '{print $1}')
    else
        err "neither sha256sum nor shasum is available; refusing to install without verification."
    fi
    _expected=$(printf '%s' "$_expected" | tr 'A-F' 'a-f')
    _actual=$(printf '%s' "$_actual" | tr 'A-F' 'a-f')
    if [ "$_actual" != "$_expected" ]; then
        err "checksum verification FAILED for ${_tarball} (expected $_expected, got $_actual) — refusing to install."
    fi

    # --no-same-owner/--no-same-permissions: don't let a substituted archive
    # choose the installed mode. Without them, `mv` preserves the member mode
    # and `chmod +x` only *adds* bits, so a member with mode 04755 would land
    # setuid-root under the documented sudo install (ADV-P1 F-P1-005).
    tar --no-same-owner --no-same-permissions -xzf "$TMP/$_tarball" -C "$TMP" \
        || err "could not extract ${_tarball} — malformed or truncated archive."
    # ADV-P2 F-P2-004: `[ -f ]` follows symlinks, so a symlink member would
    # pass, `mv` would relocate the *link*, and `chmod` would then follow it
    # — a root-privileged arbitrary chmod under the documented sudo install.
    if [ -L "$TMP/$_stem/$_base" ]; then
        err "${_tarball} contains ${_stem}/${_base} as a symlink — refusing to install."
    fi
    [ -f "$TMP/$_stem/$_base" ] \
        || err "${_tarball} did not contain ${_stem}/${_base} — malformed release artifact, please file a bug."

    mkdir -p "$INSTALL_DIR" || err "could not create $INSTALL_DIR."

    # ADV-P2 F-P2-003: $TMP (mktemp -d → /tmp or $TMPDIR) is routinely a
    # different filesystem from $INSTALL_DIR, so `mv` cannot rename() and
    # falls back to open(dst, O_WRONLY|O_CREAT|O_TRUNC) — which *follows a
    # destination symlink*, as does a plain `chmod`. Operators who manage
    # ~/.local/bin with stow/chezmoi/Homebrew commonly have `otsniff` as a
    # symlink, and re-running this installer is the documented upgrade path.
    # An interrupted cross-device mv also leaves a truncated file that the
    # following chmod makes executable.
    #
    # So: land the bytes on the *destination* filesystem under a temporary
    # name, set the mode there, then rename into place. A same-directory
    # rename is atomic and replaces a destination symlink rather than writing
    # through it — matching what packs.rs::add() does in the Rust copy.
    _staged="$INSTALL_DIR/.${_base}.tmp.$$"
    rm -f "$_staged"
    if command -v install >/dev/null 2>&1; then
        # `install -m` sets the mode atomically on create.
        install -m 0755 "$TMP/$_stem/$_base" "$_staged" \
            || err "could not write to $INSTALL_DIR — re-run with write access to that directory, or set OTSNIFF_INSTALL_DIR."
    else
        cp "$TMP/$_stem/$_base" "$_staged" \
            || err "could not write to $INSTALL_DIR — re-run with write access to that directory, or set OTSNIFF_INSTALL_DIR."
        chmod 0755 "$_staged" || err "could not chmod $_staged."
    fi

    # Strip macOS Gatekeeper quarantine (the binary isn't notarized; without
    # this the user gets a popup blocking the binary). Done before the rename
    # so the installed path is never briefly quarantined. `xattr -d` exits
    # non-zero printing "No such xattr" when the attribute was never set,
    # which is the normal case here — curl does not quarantine (F-P2-036).
    if [ "$OS" = "apple-darwin" ] && command -v xattr >/dev/null 2>&1; then
        if xattr -p com.apple.quarantine "$_staged" >/dev/null 2>&1; then
            xattr -d com.apple.quarantine "$_staged" \
                || warn "could not clear the macOS quarantine attribute on $_base; Gatekeeper may block it."
        fi
    fi

    mv -f "$_staged" "$INSTALL_DIR/$_base" \
        || err "could not move the staged binary into place at $INSTALL_DIR/$_base."
}

# ── Install core ────────────────────────────────────────────────
install_artifact "$BIN_NAME"

# ── Install requested packs ─────────────────────────────────────
INSTALLED_PACKS=""
FAILED_PACKS=""
if [ -n "$PACKS" ]; then
    # Comma-separated. `set -f` disables globbing for the split below —
    # otherwise a pack name containing `*` or `?` would expand against the
    # CWD before it was ever validated (ADV-P1 F-P1-021).
    set -f
    # Save and restore rather than `unset IFS`: under `set -u` a later
    # `$IFS` read would then die with `IFS: unbound variable` — which is
    # exactly what the PATH-membership loop at the end of this script did
    # until tests/install_sh.rs exercised the pack path.
    _pack_ifs="${IFS- }"
    IFS=','
    # shellcheck disable=SC2086  # deliberate split on IFS=','
    set -- $PACKS
    IFS="$_pack_ifs"
    set +f
    for pack in "$@"; do
        # ADV-P2 F-P2-043: this used to be `tr -d '[:space:]'`, which deletes
        # *internal* whitespace too despite the comment claiming it trimmed
        # surrounding space — so `--packs "we b"` silently installed `web`,
        # while the Rust copy rejects the same input. Trim the ends only and
        # let the charset check below reject anything that had a space in it.
        pack=$(printf '%s' "$pack" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -n "$pack" ] || continue
        # Same 64-byte cap as packs::is_valid_name, so a name the installer
        # accepts is one `otsniff pack add` would also accept.
        case "$pack" in
            *[!A-Za-z0-9_-]*)
                warn "skipping invalid pack name '$pack' — expected letters, digits, '-' or '_'."
                FAILED_PACKS="$FAILED_PACKS $pack"
                continue ;;
        esac
        if [ "${#pack}" -gt 64 ]; then
            warn "skipping pack name longer than 64 characters."
            FAILED_PACKS="$FAILED_PACKS <oversized>"
            continue
        fi
        info "installing pack: $pack"
        # A pack failure must not sink a successful core install: the core is
        # already on disk and working, and aborting here would skip the
        # success banner entirely, so a single typo'd pack name looked like
        # nothing installed at all (ADV-P1 F-P1-020). Packs are also
        # run-verified, the same standard docs/specs/install-script.md sets
        # for the core.
        #
        # ADV-P2 F-P2-025: the explicit `set -e` inside the subshell is
        # load-bearing. A subshell used as an `if` condition inherits errexit
        # *suppression* from the enclosing AND-OR context, so without it a
        # failing tar/mkdir/mv would not abort the subshell and it could exit
        # 0 having installed nothing.
        _pack_ok=no
        if ( set -e; install_artifact "${BIN_NAME}-${pack}" ); then
            # ADV-P2 F-P2-014: run-verify happens *after* the binary is in
            # place, so a pack that installs but cannot execute used to be
            # reported FAILED while staying mode-0755 in $INSTALL_DIR — where
            # `otsniff pack list` reports it installed and dispatch runs it.
            # Reported-failed and present-on-disk must not both be true.
            if "$INSTALL_DIR/${BIN_NAME}-${pack}" --help >/dev/null 2>&1; then
                _pack_ok=yes
            else
                warn "pack '$pack' installed but would not run — removing it so it isn't left half-installed."
                rm -f "$INSTALL_DIR/${BIN_NAME}-${pack}"
            fi
        fi
        if [ "$_pack_ok" = yes ]; then
            INSTALLED_PACKS="$INSTALLED_PACKS $pack"
        else
            warn "pack '$pack' could not be installed — the core is fine; retry with: $BIN_NAME pack add $pack"
            FAILED_PACKS="$FAILED_PACKS $pack"
        fi
    done
fi

# ── Verify it runs ──────────────────────────────────────────────
if ! "$INSTALL_DIR/$BIN_NAME" --version >/dev/null 2>&1; then
    err "binary installed at $INSTALL_DIR/$BIN_NAME but failed to run. Try chmod +x and re-run; if that doesn't help, file a bug."
fi
INSTALLED_VERSION=$("$INSTALL_DIR/$BIN_NAME" --version)

trap - EXIT
rm -rf "$TMP"

# ── Print success + PATH warning if needed ──────────────────────
echo
echo "  Installed: $INSTALL_DIR/$BIN_NAME"
echo "  Version:   $INSTALLED_VERSION"
if [ -n "$INSTALLED_PACKS" ]; then
    echo "  Packs:    $INSTALLED_PACKS"
fi
if [ -n "$FAILED_PACKS" ]; then
    echo "  FAILED:   $FAILED_PACKS  (core install is fine — retry with '$BIN_NAME pack add <name>')"
fi

# ADV-P2 F-P2-040: `case ":$PATH:" in *":$INSTALL_DIR:"*)` treats the install
# dir as a *glob pattern* on the right-hand side, so a directory containing
# `*`, `?` or `[` mis-reports PATH membership in either direction. Compare
# each PATH entry literally instead.
on_path=no
_saved_ifs="${IFS- }"
IFS=':'
set -f
for _entry in $PATH; do
    # `[ … ] && on_path=yes` would exit the script under `set -e` on the
    # first non-matching entry: the list's status is the test's.
    if [ "$_entry" = "$INSTALL_DIR" ]; then
        on_path=yes
    fi
done
set +f
IFS=$_saved_ifs

case "$on_path" in
    yes)
        echo
        echo "  Try it: $BIN_NAME --help"
        echo "  Optional components: $BIN_NAME pack list"
        ;;
    *)
        echo
        echo "  WARNING: $INSTALL_DIR is not on your PATH."
        echo "  Add this to your shell profile (~/.zshrc, ~/.bashrc, etc.):"
        echo
        echo "      export PATH=\"$INSTALL_DIR:\$PATH\""
        echo
        echo "  Then reload your shell and run: $BIN_NAME --help"
        ;;
esac

# A requested pack that didn't install is a partial failure: the banner above
# reports it either way, but automation should still see a non-zero status.
[ -z "$FAILED_PACKS" ] || exit 1
