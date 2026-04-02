#!/usr/bin/env bash
# BoneStack installer / updater

set -euo pipefail

REPO_URL="https://github.com/khbarkar/BoneStack.git"
INSTALL_DIR="$HOME/.bonestack"
BIN_DIR="$HOME/.local/bin"
BIN_PATH="$BIN_DIR/bonestack"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

echo "Installing BoneStack..."

need_cmd git
need_cmd go

mkdir -p "$BIN_DIR"

if [ ! -d "$INSTALL_DIR/.git" ]; then
  git clone "$REPO_URL" "$INSTALL_DIR"
else
  git -C "$INSTALL_DIR" pull --ff-only
fi

echo "Building BoneStack..."
(
  cd "$INSTALL_DIR"
  go build -o bonestack ./cmd/bonestack/main.go
)

ln -sf "$INSTALL_DIR/bonestack" "$BIN_PATH"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo
  echo "Add this to your shell profile:"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

VERSION="$(git -C "$INSTALL_DIR" describe --tags --always 2>/dev/null || echo unknown)"

echo
echo "[ok] BoneStack installed"
echo "Version: $VERSION"
echo "Binary:  $BIN_PATH"
echo
echo "Run: bonestack"
echo "Update later by rerunning this same install command."
