#!/usr/bin/env bash
# Cross-compile relay/wg → libtetherand_wg.so for arm64-android and
# stage the result under android/app/src/main/jniLibs/arm64-v8a/.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY="$HERE/relay"
DEST="$HERE/android/app/src/main/jniLibs/arm64-v8a"

NDK="${ANDROID_NDK_HOME:-$(ls -d $HOME/Library/Android/sdk/ndk/* 2>/dev/null | head -1)}"
[[ -d "$NDK" ]] || { echo "error: NDK not found. Set ANDROID_NDK_HOME."; exit 1; }

if [[ -d "$NDK/toolchains/llvm/prebuilt/darwin-x86_64" ]]; then
  TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64"
elif [[ -d "$NDK/toolchains/llvm/prebuilt/darwin-arm64" ]]; then
  TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-arm64"
else
  echo "error: NDK toolchain not found under $NDK/toolchains/llvm/prebuilt/"; exit 1
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"

# Strip build-host PII from the resulting .so: panic location strings
# otherwise embed the absolute paths of every Rust source touched
# (e.g. /Users/<your-mac-user>/.cargo/registry/...). --remap-path-prefix
# rewrites those at compile time. We map $HOME → "~" and $CARGO_HOME →
# "/cargo" so no real path leaks into the artifact.
RUST_REMAP="--remap-path-prefix=$HOME=~ --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$RELAY=/build"
export RUSTFLAGS="${RUSTFLAGS:-} $RUST_REMAP"

cd "$RELAY"
cargo build --release --target aarch64-linux-android -p tetherand-wg
mkdir -p "$DEST"
cp "$RELAY/target/aarch64-linux-android/release/libtetherand_wg.so" "$DEST/"
echo "  ✓ libtetherand_wg.so -> $DEST"
file "$DEST/libtetherand_wg.so" 2>/dev/null | head -1
