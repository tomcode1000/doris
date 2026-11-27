#!/usr/bin/env bash
# Copy the doris package (and optional extra paths) onto doris-home.
# Works around `sprite file push` path bugs on Windows by streaming a tarball.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
S="${SPRITE_BIN:-$LOCALAPPDATA/Programs/Sprite/sprite.exe}"
ORG="${SPRITE_ORG:?set SPRITE_ORG to your Fly org}"
TARGET="${1:-doris-home}"
shift || true
PATHS=("doris" "web" "$@")
B=$(tar --exclude='__pycache__' -czf - "${PATHS[@]}" 2>/dev/null | base64 -w0)
"$S" exec --no-stdin -o "$ORG" -s "$TARGET" -- bash -c \
  "mkdir -p /home/sprite/app && cd /home/sprite/app && echo $B | base64 -d | tar -xzmf - && echo deployed: \$(ls)"
