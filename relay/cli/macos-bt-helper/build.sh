#!/usr/bin/env bash
# Build the tetherand-bt-bridge helper. Spawned by the tetherand CLI on
# macOS for `tetherand run --transport bt` and `tetherand bt list`.
#
# Output lands at:
#   bin/tetherand-bt-bridge
# alongside the other tetherand release artifacts.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$REPO_ROOT/bin/tetherand-bt-bridge"
SRC="$(dirname "$0")/tetherand-bt-bridge.swift"

if [ "$(uname)" != "Darwin" ]; then
    echo "tetherand-bt-bridge is macOS-only (IOBluetooth has no Linux/Windows equivalent)"
    echo "skipping build on $(uname)"
    exit 0
fi

mkdir -p "$REPO_ROOT/bin"
swiftc -O -o "$OUT" "$SRC" \
    -framework IOBluetooth \
    -framework Foundation
echo "built $OUT ($(file "$OUT" | cut -d: -f2- | xargs))"
