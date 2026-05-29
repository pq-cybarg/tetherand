#!/usr/bin/env bash
# Cross-compile the tetherand-pt binary for arm64-v8a Android.
#
# Requires NDK_HOME pointing at the Android NDK r26+ installation.
# Output lands in android/app/src/main/jniLibs/arm64-v8a/libtetherand_pt.so
# (the `lib*.so` name is what Android's APK packer keeps; PtBinaryStager
# renames it to extension-less `tetherand-pt` at runtime).

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
cargo build --release --target=$TARGET -p tetherand-pt

OUT_DIR=../android/app/src/main/jniLibs/arm64-v8a
mkdir -p "$OUT_DIR"
cp target/$TARGET/release/tetherand-pt "$OUT_DIR/libtetherand_pt.so"
ls -lh "$OUT_DIR/libtetherand_pt.so"

echo "M6.x tetherand-pt cross-compiled + staged."
