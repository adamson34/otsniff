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

REPO="adamson34/otsniff"
BIN_NAME="otsniff"
INSTALL_DIR="${OTSNIFF_INSTALL_DIR:-$HOME/.local/bin}"

err() { echo "otsniff-install: $*" >&2; exit 1; }
warn() { echo "otsniff-install: WARNING: $*" >&2; }
info() { echo "otsniff-install: $*"; }

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

# ── Pick version ────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
    info "looking up latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [ -n "$VERSION" ] || err "could not determine latest release. Set OTSNIFF_VERSION=vX.Y.Z and retry."
fi

# ── Stage in temp dir ───────────────────────────────────────────
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t 'otsniff-install')
trap 'rm -rf "$TMP"' EXIT INT TERM

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
    if ! curl -fSL "$_url" -o "$TMP/$_tarball" 2>/dev/null; then
        err "download failed: $_url
  Check that $VERSION publishes this artifact at https://github.com/$REPO/releases."
    fi
    curl -fsSL "${_url}.sha256" -o "$TMP/${_tarball}.sha256" \
        || err "checksum sidecar download failed for ${_tarball}."

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
    tar --no-same-owner --no-same-permissions -xzf "$TMP/$_tarball" -C "$TMP"
    [ -f "$TMP/$_stem/$_base" ] \
        || err "${_tarball} did not contain ${_stem}/${_base} — malformed release artifact, please file a bug."

    mkdir -p "$INSTALL_DIR"
    mv "$TMP/$_stem/$_base" "$INSTALL_DIR/"
    chmod 0755 "$INSTALL_DIR/$_base"

    # Strip macOS Gatekeeper quarantine (the binary isn't notarized;
    # without this the user gets a popup blocking the binary).
    if [ "$OS" = "apple-darwin" ]; then
        xattr -d com.apple.quarantine "$INSTALL_DIR/$_base" 2>/dev/null || true
    fi
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
    IFS=','
    # shellcheck disable=SC2086  # deliberate split on IFS=','
    set -- $PACKS
    unset IFS
    set +f
    for pack in "$@"; do
        # Trim surrounding whitespace, then validate: pack names are an
        # identifier namespace, and this value becomes a filename and a URL.
        pack=$(printf '%s' "$pack" | tr -d '[:space:]')
        [ -n "$pack" ] || continue
        case "$pack" in
            *[!A-Za-z0-9_-]*)
                warn "skipping invalid pack name '$pack' — expected letters, digits, '-' or '_'."
                FAILED_PACKS="$FAILED_PACKS $pack"
                continue ;;
        esac
        info "installing pack: $pack"
        # A pack failure must not sink a successful core install: the core is
        # already on disk and working, and aborting here would skip the
        # success banner entirely, so a single typo'd pack name looked like
        # nothing installed at all (ADV-P1 F-P1-020). Packs are also
        # run-verified, the same standard docs/specs/install-script.md sets
        # for the core.
        if ( install_artifact "${BIN_NAME}-${pack}" ) \
            && "$INSTALL_DIR/${BIN_NAME}-${pack}" --help >/dev/null 2>&1; then
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

case ":$PATH:" in
    *":$INSTALL_DIR:"*)
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
