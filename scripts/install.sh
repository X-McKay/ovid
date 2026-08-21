#!/bin/sh
# Ovid installer.
#
#   curl -fsSL https://raw.githubusercontent.com/X-McKay/ovid/main/scripts/install.sh | sh
#
# Strategy: download the prebuilt binary for this platform from the
# latest GitHub release (sha256-verified); when no release asset exists
# (or on an unsupported target), fall back to `cargo install` from git.
#
# Environment overrides:
#   OVID_INSTALL_DIR   install destination (default: ~/.local/bin)
#   OVID_REPO          owner/repo to install from (default: X-McKay/ovid)
#   OVID_REPO_URL      git URL for the cargo fallback (default: GitHub)
#   OVID_VERSION       release tag to install (default: latest)
set -eu

REPO="${OVID_REPO:-X-McKay/ovid}"
REPO_URL="${OVID_REPO_URL:-https://github.com/${REPO}}"
INSTALL_DIR="${OVID_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${OVID_VERSION:-latest}"

say() { printf 'ovid install: %s\n' "$*"; }
fail() { printf 'ovid install: error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required"

# ---------------------------------------------------------------- platform
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
      *) TARGET="" ;;
    esac ;;
  Darwin)
    case "$ARCH" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *) TARGET="" ;;
    esac ;;
  *) TARGET="" ;;
esac

# ------------------------------------------------------- prebuilt release
install_from_release() {
  [ -n "$TARGET" ] || return 1
  if [ "$VERSION" = "latest" ]; then
    base="https://github.com/${REPO}/releases/latest/download"
  else
    base="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  asset="ovid-${TARGET}.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  say "trying prebuilt release: ${base}/${asset}"
  curl -fsSL -o "$tmp/$asset" "${base}/${asset}" 2>/dev/null || return 1

  # Verify the checksum when the release publishes one.
  if curl -fsSL -o "$tmp/$asset.sha256" "${base}/${asset}.sha256" 2>/dev/null; then
    ( cd "$tmp" && sha256sum -c "$asset.sha256" >/dev/null 2>&1 ) \
      || ( cd "$tmp" && shasum -a 256 -c "$asset.sha256" >/dev/null 2>&1 ) \
      || fail "checksum verification failed for $asset"
    say "sha256 verified"
  else
    say "warning: no checksum published for $asset; skipping verification"
  fi

  mkdir -p "$INSTALL_DIR"
  tar -xzf "$tmp/$asset" -C "$tmp"
  install -m 0755 "$tmp/ovid" "$INSTALL_DIR/ovid"
  return 0
}

# ------------------------------------------------------- cargo fallback
install_from_source() {
  command -v cargo >/dev/null 2>&1 || fail \
    "no prebuilt binary for ${OS}/${ARCH} and cargo is not installed.
  Install Rust first:  curl -fsSL https://sh.rustup.rs | sh
  then re-run this installer, or run:
    cargo install --locked --git ${REPO_URL} ovid-cli"
  say "building from source with cargo (a few minutes)..."
  cargo install --locked --git "$REPO_URL" ovid-cli
  # cargo installs to ~/.cargo/bin/ovid; nothing else to do.
  INSTALL_DIR="$HOME/.cargo/bin"
  return 0
}

if install_from_release; then
  say "installed prebuilt binary to $INSTALL_DIR/ovid"
else
  say "no prebuilt release for this platform/version; falling back to cargo"
  install_from_source
fi

# ----------------------------------------------------------- post-install
"$INSTALL_DIR/ovid" --version >/dev/null 2>&1 \
  || fail "installed binary failed to run from $INSTALL_DIR/ovid"

case ":$PATH:" in
  *:"$INSTALL_DIR":*) ;;
  *) say "note: add $INSTALL_DIR to your PATH, e.g.:
    export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

if [ "$OS" = "Linux" ] && ! command -v strace >/dev/null 2>&1; then
  say "note: install strace for boundary observation (e.g. apt-get install strace);"
  say "      without it, runs execute unobserved and manifests say so"
fi
if [ "$OS" = "Darwin" ]; then
  say "note: on macOS, native execution is unavailable (static analysis works);"
  say "      install the msb CLI (https://microsandbox.dev) and use --backend microsandbox"
fi

say "done: $("$INSTALL_DIR/ovid" --version 2>/dev/null || echo ovid)"
