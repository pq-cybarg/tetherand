#!/usr/bin/env bash
# Cross-compile libtetherand_tor.so for arm64-v8a Android.
#
# Requires NDK_HOME pointing at the Android NDK r26+ installation.
# Output lands in android/app/src/main/jniLibs/arm64-v8a/.
#
# arti-client + tor-rtcompat + rustls compile cleanly against
# aarch64-linux-android-clang when given a matching CC. We do NOT
# enable any OpenSSL-using arti feature — rustls keeps the NDK build
# self-contained.

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

cd "$(dirname "$0")/../relay"
cargo build --release --target=$TARGET -p tetherand-tor --features android

OUT_DIR=../android/app/src/main/jniLibs/arm64-v8a
mkdir -p "$OUT_DIR"
cp target/$TARGET/release/libtetherand_tor.so "$OUT_DIR/"
ls -lh "$OUT_DIR/libtetherand_tor.so"

echo "M6 native Tor lib built + staged."
