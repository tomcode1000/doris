#!/usr/bin/env bash
# Copy the doris package, the website (and optional extra paths) onto a Sprite.
# `sprite file push` mangles paths on Windows and one command line is capped at
# ~32 KB there, so the tarball is streamed as base64 in chunks, then unpacked.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
S="${SPRITE_BIN:-$LOCALAPPDATA/Programs/Sprite/sprite.exe}"
ORG="${SPRITE_ORG:?set SPRITE_ORG to your Fly org}"
TARGET="${1:-doris-home}"
shift || true
PATHS=("doris" "web" "$@")
B=$(tar --exclude='__pycache__' -czf - "${PATHS[@]}" 2>/dev/null | base64 -w0)
CHUNK=20000
run() { "$S" exec --no-stdin -o "$ORG" -s "$TARGET" -- bash -c "$1"; }
run ": > /tmp/deploy.b64"
for ((i = 0; i < ${#B}; i += CHUNK)); do
  run "printf %s '${B:i:CHUNK}' >> /tmp/deploy.b64"
done
run "mkdir -p /home/sprite/app && cd /home/sprite/app && base64 -d /tmp/deploy.b64 | tar -xzmf - && echo deployed: \$(ls)"
