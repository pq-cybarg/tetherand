#!/usr/bin/env bash
# Cross-compile libtetherand_nym.so for arm64-v8a Android.
#
# Requires:
#   NDK_HOME pointing at the Android NDK r26+ installation
#   (Optional) rustup nightly toolchain if nym-sdk's transitive deps
#   need the nightly. The current --features with-sdk path pulls
#   nym-noise which has a closure-type-inference issue on rustc 1.83+
#   — point your default toolchain at a working nightly via
#       rustup override set nightly-2025-09-15
#   inside relay/ before invoking this script.

set -euo pipefail

: "${NDK_HOME:?Set NDK_HOME to your Android NDK installation}"

TARGET=aarch64-linux-android
API=26
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt"
HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"
if [ ! -d "$TOOLCHAIN/$HOST_TAG" ]; then HOST_TAG="darwin-x86_64"; fi

export CC_aarch64_linux_android="$TOOLCHAIN/$HOST_TAG/bin/aarch64-linux-android${API}-clang"
export CXX_aarch64_linux_android="$TOOLCHAIN/$HOST_TAG/bin/aarch64-linux-android${API}-clang++"
export AR_aarch64_linux_android="$TOOLCHAIN/$HOST_TAG/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_REMAP="--remap-path-prefix=$HOME=~ --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$REPO_ROOT/relay=/build"
export RUSTFLAGS="${RUSTFLAGS:-} $RUST_REMAP"

cd "$REPO_ROOT/relay"
cargo build --release --target=$TARGET -p tetherand-nym --features "android,with-sdk"

OUT_DIR=../android/app/src/main/jniLibs/arm64-v8a
mkdir -p "$OUT_DIR"
cp target/$TARGET/release/libtetherand_nym.so "$OUT_DIR/"
ls -lh "$OUT_DIR/libtetherand_nym.so"

echo "M5 native Nym lib built + staged."
