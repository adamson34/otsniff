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
info() { echo "otsniff-install: $*"; }

# ── Parse args ──────────────────────────────────────────────────
# Positional arg is the version (kept for backwards compatibility);
# --packs takes a comma-separated list. Pack names aren't validated here —
# the installer has no catalog, so a typo surfaces as a clear download
# failure naming the artifact it looked for.
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
    if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$TMP" && sha256sum -c "${_tarball}.sha256" >/dev/null ) \
            || err "checksum verification FAILED for ${_tarball} — refusing to install."
    elif command -v shasum >/dev/null 2>&1; then
        ( cd "$TMP" && shasum -a 256 -c "${_tarball}.sha256" >/dev/null ) \
            || err "checksum verification FAILED for ${_tarball} — refusing to install."
    else
        err "neither sha256sum nor shasum is available; refusing to install without verification."
    fi

    tar xzf "$TMP/$_tarball" -C "$TMP"
    [ -f "$TMP/$_stem/$_base" ] \
        || err "${_tarball} did not contain ${_stem}/${_base} — malformed release artifact, please file a bug."

    mkdir -p "$INSTALL_DIR"
    mv "$TMP/$_stem/$_base" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$_base"

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
if [ -n "$PACKS" ]; then
    # Comma-separated; tolerate spaces around entries.
    for pack in $(echo "$PACKS" | tr ',' ' '); do
        [ -n "$pack" ] || continue
        info "installing pack: $pack"
        install_artifact "${BIN_NAME}-${pack}"
        INSTALLED_PACKS="$INSTALLED_PACKS $pack"
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
