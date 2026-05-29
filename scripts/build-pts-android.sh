#!/usr/bin/env bash
# Cross-compile the upstream Go pluggable-transport clients for
# arm64-v8a Android:
#   - snowflake-client (from gitlab.torproject.org/tpo/anti-censorship/
#                       pluggable-transports/snowflake)
#   - conjure-client   (from github.com/refraction-networking/conjure)
#
# Output lands in android/app/src/main/jniLibs/arm64-v8a/ with `libxxx.so`
# names so the APK packer keeps them; PtBinaryStager renames at runtime.
#
# Requires:
#   GOROOT pointing at a Go 1.22+ install
#   NDK_HOME pointing at Android NDK r26+

set -euo pipefail

: "${GOROOT:?Set GOROOT to your Go 1.22+ install (snowflake + conjure are Go)}"
: "${NDK_HOME:?Set NDK_HOME to your Android NDK installation}"

API=26
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt"
HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"
if [ ! -d "$TOOLCHAIN/$HOST_TAG" ]; then HOST_TAG="darwin-x86_64"; fi
export PATH="$GOROOT/bin:$PATH"
export CC="$TOOLCHAIN/$HOST_TAG/bin/aarch64-linux-android${API}-clang"
export CGO_ENABLED=1
export GOOS=android
export GOARCH=arm64

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/android/app/src/main/jniLibs/arm64-v8a"
WORK="$REPO_ROOT/.pt-build"
mkdir -p "$OUT_DIR" "$WORK"

# -- snowflake -----------------------------------------------------------
if [ ! -d "$WORK/snowflake" ]; then
    git clone --depth 1 https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake.git "$WORK/snowflake"
fi
(cd "$WORK/snowflake/client" && go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/libsnowflake_client.so" .)

# -- conjure -------------------------------------------------------------
if [ ! -d "$WORK/conjure" ]; then
    git clone --depth 1 https://github.com/refraction-networking/conjure.git "$WORK/conjure"
fi
(cd "$WORK/conjure/cmd/client" && go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/libconjure_client.so" .)

ls -lh "$OUT_DIR/libsnowflake_client.so" "$OUT_DIR/libconjure_client.so"
echo "M6.x snowflake + conjure cross-compiled + staged."
