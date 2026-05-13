#!/usr/bin/env bash
# install.sh — SLATE installer
#
# Builds and installs the slate binary, then runs init.
# Requires: Go 1.22+
#
# Usage:
#   sudo bash install.sh [--department "Dept Name"] [--node "node-001"]

set -euo pipefail

info()  { echo "[install] $*"; }
fatal() { echo "[install] FATAL: $*" >&2; exit 1; }

DEPT=""
NODE="node-001"
INSTALL_DIR="/usr/local/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --department) DEPT="$2"; shift 2 ;;
    --node)       NODE="$2"; shift 2 ;;
    *) fatal "Unknown arg: $1" ;;
  esac
done

command -v go &>/dev/null || fatal "Go is required. Install from https://go.dev/dl/"
GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
if [[ "$(printf '%s\n' "1.22" "$GO_VER" | sort -V | head -1)" != "1.22" ]]; then
  fatal "Go 1.22+ required (found $GO_VER)"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info "Building SLATE…"
go mod tidy
go build -trimpath -ldflags="-s -w" -o slate ./cmd/slate
install -m 0755 slate "$INSTALL_DIR/slate"
rm -f slate
info "slate installed → $INSTALL_DIR/slate"

SOUL_DST="$HOME/.slate/soul.toml"
if [[ -f "$SOUL_DST" ]]; then
  info "Soul file already present — skipping."
else
  mkdir -p "$HOME/.slate"
  cp "$SCRIPT_DIR/payload/default-soul.toml" "$SOUL_DST"
  chmod 0400 "$SOUL_DST"
  info "Soul file installed → $SOUL_DST"
fi

INIT_ARGS=()
[[ -n "$DEPT" ]] && INIT_ARGS+=(--department "$DEPT")
[[ -n "$NODE" ]] && INIT_ARGS+=(--node "$NODE")

if [[ -d "$HOME/.slate/primary" ]]; then
  info "SLATE already initialized — skipping init."
else
  info "Initializing SLATE…"
  "$INSTALL_DIR/slate" init "${INIT_ARGS[@]}"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  SLATE installed.                                             ║"
echo "║                                                               ║"
echo "║  Add your first token:                                        ║"
echo '║  slate token add --role chief --name "Chief Johnson"          ║'
echo "║                                                               ║"
echo "║  Then start the dashboard:                                    ║"
echo "║  slate serve                                                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
