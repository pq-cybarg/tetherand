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

: "${GOROOT:?Set GOROOT to your Go install (snowflake + conjure are Go)}"
: "${NDK_HOME:?Set NDK_HOME to your Android NDK installation}"

# Snowflake's transitive dep github.com/wlynxg/anet uses an internal
# net.zoneCache symbol that was removed in Go 1.26. Until upstream
# patches anet, snowflake needs Go 1.22..1.25. If the GOROOT points at
# 1.26+, look for a sibling 1.25 install (Homebrew formula `go@1.25` or
# a goenv shim) and switch to it for the snowflake build.
GOVER="$("$GOROOT/bin/go" env GOVERSION 2>/dev/null | sed 's/^go//')"
SNOWFLAKE_GOROOT="$GOROOT"
case "$GOVER" in
    1.26*|1.27*|1.28*|1.29*)
        for candidate in \
            "$(brew --prefix go@1.25 2>/dev/null)/libexec" \
            "$(brew --prefix go@1.22 2>/dev/null)/libexec" \
            "$HOME/sdk/go1.25" "$HOME/sdk/go1.22"; do
            if [ -x "$candidate/bin/go" ]; then
                SNOWFLAKE_GOROOT="$candidate"
                break
            fi
        done
        if [ "$SNOWFLAKE_GOROOT" = "$GOROOT" ]; then
            echo "warn: Go $GOVER is too new for snowflake (upstream wlynxg/anet uses removed net.zoneCache)."
            echo "warn: skipping snowflake. Install Go 1.22-1.25 (e.g. 'brew install go@1.25')."
            BUILD_SNOWFLAKE=0
        else
            echo "  Using $SNOWFLAKE_GOROOT for snowflake (avoids Go 1.26 net.zoneCache regression)."
            BUILD_SNOWFLAKE=1
        fi ;;
    *)
        BUILD_SNOWFLAKE=1 ;;
esac

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
if [ "${BUILD_SNOWFLAKE:-1}" = "1" ]; then
    if [ ! -d "$WORK/snowflake" ]; then
        git clone --depth 1 https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake.git "$WORK/snowflake"
    fi
    SNOWFLAKE_GO="$SNOWFLAKE_GOROOT/bin/go"
    # -checklinkname=0 is required because snowflake's transitive
    # github.com/wlynxg/anet uses //go:linkname against net.zoneCache,
    # which Go 1.23+ restricts by default. anet upstream documents
    # this in their README as the official fix.
    (cd "$WORK/snowflake/client" && GOROOT="$SNOWFLAKE_GOROOT" PATH="$SNOWFLAKE_GOROOT/bin:$PATH" GOTOOLCHAIN=local "$SNOWFLAKE_GO" build -trimpath -ldflags="-s -w -checklinkname=0" -o "$OUT_DIR/libsnowflake_client.so" .)
else
    echo "  Skipping snowflake (no Go 1.22-1.25 available)."
fi

# -- conjure (via gotapdance — the conjure repo itself ships server-side
#    binaries; the maintained client lives at refraction-networking/gotapdance) ----
if [ ! -d "$WORK/gotapdance" ]; then
    git clone --depth 1 https://github.com/refraction-networking/gotapdance.git "$WORK/gotapdance"
fi
(cd "$WORK/gotapdance/cli" && go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/libconjure_client.so" .)

ls -lh "$OUT_DIR/libsnowflake_client.so" "$OUT_DIR/libconjure_client.so"
echo "M6.x snowflake + conjure cross-compiled + staged."
