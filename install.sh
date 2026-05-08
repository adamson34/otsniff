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
# Env vars (alternate ways to override):
#   OTSNIFF_VERSION       Pin a specific tag (also takes the first positional arg).
#   OTSNIFF_INSTALL_DIR   Where to put the binary (default: $HOME/.local/bin).
#
# What this does:
#   1. Detect OS/arch and pick the matching release tarball.
#   2. Download tarball + .sha256 sidecar from the GitHub release.
#   3. Verify the checksum.
#   4. Extract, move the binary to the install dir, strip macOS quarantine.
#   5. Confirm the binary runs and warn if the install dir isn't on PATH.
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
# Precedence: positional arg > OTSNIFF_VERSION env var > latest release.
VERSION="${1:-${OTSNIFF_VERSION:-}}"
if [ -z "$VERSION" ]; then
    info "looking up latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [ -n "$VERSION" ] || err "could not determine latest release. Set OTSNIFF_VERSION=vX.Y.Z and retry."
fi

TARBALL="otsniff-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/$REPO/releases/download/${VERSION}/${TARBALL}"
SHA_URL="${URL}.sha256"

# ── Stage in temp dir ───────────────────────────────────────────
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t 'otsniff-install')
trap 'rm -rf "$TMP"' EXIT INT TERM

info "downloading $TARBALL..."
if ! curl -fSL "$URL" -o "$TMP/$TARBALL" 2>/dev/null; then
    err "download failed. Check that $VERSION is a real release at https://github.com/$REPO/releases."
fi
curl -fsSL "$SHA_URL" -o "$TMP/$TARBALL.sha256" \
    || err "checksum sidecar download failed."

# ── Verify checksum ─────────────────────────────────────────────
info "verifying checksum..."
cd "$TMP"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$TARBALL.sha256" >/dev/null \
        || err "checksum verification FAILED — refusing to install."
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$TARBALL.sha256" >/dev/null \
        || err "checksum verification FAILED — refusing to install."
else
    err "neither sha256sum nor shasum is available; refusing to install without verification."
fi

# ── Extract and install ─────────────────────────────────────────
info "extracting..."
tar xzf "$TARBALL"
EXTRACT_DIR="otsniff-${VERSION}-${TARGET}"

mkdir -p "$INSTALL_DIR"
mv "$EXTRACT_DIR/$BIN_NAME" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BIN_NAME"

# Strip macOS Gatekeeper quarantine (the binary isn't notarized;
# without this the user gets a popup blocking the binary).
if [ "$OS" = "apple-darwin" ]; then
    xattr -d com.apple.quarantine "$INSTALL_DIR/$BIN_NAME" 2>/dev/null || true
fi

# ── Verify it runs ──────────────────────────────────────────────
if ! "$INSTALL_DIR/$BIN_NAME" --version >/dev/null 2>&1; then
    err "binary installed at $INSTALL_DIR/$BIN_NAME but failed to run. Try chmod +x and re-run; if that doesn't help, file a bug."
fi
INSTALLED_VERSION=$("$INSTALL_DIR/$BIN_NAME" --version)

cd /
trap - EXIT
rm -rf "$TMP"

# ── Print success + PATH warning if needed ──────────────────────
echo
echo "  Installed: $INSTALL_DIR/$BIN_NAME"
echo "  Version:   $INSTALLED_VERSION"

case ":$PATH:" in
    *":$INSTALL_DIR:"*)
        echo
        echo "  Try it: $BIN_NAME --help"
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
