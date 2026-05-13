#!/usr/bin/env bash
# =============================================================================
# make-checksums.sh — Run this on your BUILD MACHINE before deployment
# Never run this on the target machine
# =============================================================================
# Usage: bash make-checksums.sh
# Output:
#   - stamps soul_hash and forge_date in payload/default-soul.toml
#   - writes VERIFY.txt next to this script

set -euo pipefail

sha256() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "ERROR: No SHA256 tool available." >&2; exit 1
  fi
}

sha256_stdin() {
  if command -v sha256sum &>/dev/null; then
    sha256sum | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 | awk '{print $1}'
  else
    echo "ERROR: No SHA256 tool available." >&2; exit 1
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$SCRIPT_DIR/payload"
SOUL_FILE="$PAYLOAD_DIR/default-soul.toml"
OUT_FILE="$SCRIPT_DIR/VERIFY.txt"

if [[ ! -d "$PAYLOAD_DIR" ]]; then
  echo "ERROR: payload/ directory not found at $SCRIPT_DIR"
  exit 1
fi

# ── Stamp forge_date ──────────────────────────────────────────────────────────
TODAY="$(date -u '+%Y-%m-%d')"
awk -v d="$TODAY" '/^forge_date/ { sub(/"[^"]*"/, "\"" d "\"") } { print }' \
  "$SOUL_FILE" > "${SOUL_FILE}.tmp" && mv "${SOUL_FILE}.tmp" "$SOUL_FILE"
echo "  forge_date = $TODAY"

# ── Stamp soul_hash ───────────────────────────────────────────────────────────
# Hash the file with soul_hash blanked so the stored value is stable.
SOUL_HASH=$(awk '/^soul_hash/ { sub(/"[^"]*"/, "\"\"") } { print }' "$SOUL_FILE" | sha256_stdin)
awk -v h="$SOUL_HASH" '/^soul_hash/ { sub(/"[^"]*"/, "\"" h "\"") } { print }' \
  "$SOUL_FILE" > "${SOUL_FILE}.tmp" && mv "${SOUL_FILE}.tmp" "$SOUL_FILE"
echo "  soul_hash  = $SOUL_HASH"

# ── Hash all payload files → VERIFY.txt ──────────────────────────────────────
echo "# SLATE — Secure Log Audit for Trace Evidence — Payload Checksums" >  "$OUT_FILE"
echo "# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"                  >> "$OUT_FILE"
echo "# DO NOT EDIT — regenerate with make-checksums.sh"                  >> "$OUT_FILE"
echo ""                                                                    >> "$OUT_FILE"

COUNT=0
while IFS= read -r file; do
  rel="${file#$SCRIPT_DIR/}"
  hash=$(sha256 "$file")
  echo "$hash  $rel" >> "$OUT_FILE"
  echo "  hashed: $rel"
  (( COUNT++ )) || true
done < <(find "$PAYLOAD_DIR" -type f | sort)

echo ""
echo "Done. $COUNT file(s) hashed → VERIFY.txt"
