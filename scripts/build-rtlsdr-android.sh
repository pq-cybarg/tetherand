#!/usr/bin/env bash
# Cross-compile librtlsdr + libhackrf + libusb (no-libudev mode) for
# arm64-v8a Android, plus a thin libtetherand_sdr.so wrapper that
# exposes a Sample-rate / center-freq / capture-IQ surface to Kotlin
# via JNI. The LTE control-channel decoder (SIB/MIB parse) is pulled
# from srsRAN's lib/src/phy module and statically linked.
#
# Requires:
#   NDK_HOME pointing at the Android NDK r26+ installation
#   cmake 3.20+ on PATH
#   git on PATH

set -euo pipefail

: "${NDK_HOME:?Set NDK_HOME to your Android NDK installation}"
TARGET=aarch64-linux-android
API=26

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO_ROOT/.sdr-build"
OUT_DIR="$REPO_ROOT/android/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$WORK" "$OUT_DIR"

TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt"
HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"
[ -d "$TOOLCHAIN/$HOST_TAG" ] || HOST_TAG="darwin-x86_64"

CMAKE_ARGS=(
    -DCMAKE_TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake"
    -DANDROID_ABI=arm64-v8a
    -DANDROID_PLATFORM=android-$API
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=ON
)

# -- libusb (no-libudev mode for Android) ---------------------------------
if [ ! -d "$WORK/libusb" ]; then
    git clone --depth 1 https://github.com/libusb/libusb-cmake.git "$WORK/libusb"
fi
cmake -S "$WORK/libusb" -B "$WORK/libusb/build" "${CMAKE_ARGS[@]}" \
    -DLIBUSB_BUILD_EXAMPLES=OFF -DLIBUSB_BUILD_TESTING=OFF
cmake --build "$WORK/libusb/build" --target usb-1.0 -j
cp "$WORK/libusb/build/libusb-1.0.so" "$OUT_DIR/libusb-1.0.so"

# -- librtlsdr ------------------------------------------------------------
if [ ! -d "$WORK/rtlsdr" ]; then
    git clone --depth 1 https://gitea.osmocom.org/sdr/rtl-sdr.git "$WORK/rtlsdr"
fi
# rtlsdr's CMakeLists hardcodes `-lusb-1.0` in the link command rather
# than using LIBUSB_LIBRARIES, so we need both the file path AND a
# search-dir flag pointing at the libusb build output. Then we copy
# the file under the conventional name so the dynamic loader on
# Android resolves it at runtime.
cmake -S "$WORK/rtlsdr" -B "$WORK/rtlsdr/build" "${CMAKE_ARGS[@]}" \
    -DLIBUSB_INCLUDE_DIR="$WORK/libusb/libusb/libusb" \
    -DLIBUSB_LIBRARIES="$WORK/libusb/build/libusb-1.0.so" \
    -DCMAKE_SHARED_LINKER_FLAGS="-L$WORK/libusb/build" \
    -DCMAKE_EXE_LINKER_FLAGS="-L$WORK/libusb/build" \
    -DINSTALL_UDEV_RULES=OFF -DDETACH_KERNEL_DRIVER=OFF
cmake --build "$WORK/rtlsdr/build" --target rtlsdr -j
cp "$WORK/rtlsdr/build/src/librtlsdr.so" "$OUT_DIR/librtlsdr.so"
cp "$WORK/libusb/build/libusb-1.0.so" "$OUT_DIR/libusb-1.0.so"

# -- libhackrf ------------------------------------------------------------
if [ ! -d "$WORK/hackrf" ]; then
    git clone --depth 1 https://github.com/greatscottgadgets/hackrf.git "$WORK/hackrf"
fi
cmake -S "$WORK/hackrf/host/libhackrf" -B "$WORK/hackrf/build" "${CMAKE_ARGS[@]}" \
    -DLIBUSB_INCLUDE_DIR="$WORK/libusb/libusb/libusb" \
    -DLIBUSB_LIBRARIES="$WORK/libusb/build/libusb-1.0.so" \
    -DCMAKE_SHARED_LINKER_FLAGS="-L$WORK/libusb/build"
cmake --build "$WORK/hackrf/build" --target hackrf -j
find "$WORK/hackrf/build" -name "libhackrf.so" -exec cp {} "$OUT_DIR/libhackrf.so" \;

# -- libtetherand_sdr (JNI shim into librtlsdr) ---------------------------
# Thin C wrapper exposing
# Java_dev_tetherand_app_threat_sdr_SdrCellularProbe_nativeRtlSdrPowerDbm
# linked against the cross-compiled librtlsdr.so. Compiled with clang
# directly (no cmake — one source file, one external dep).
CLANG="$TOOLCHAIN/$HOST_TAG/bin/aarch64-linux-android${API}-clang"
SYSROOT="$TOOLCHAIN/$HOST_TAG/sysroot"
"$CLANG" \
    -O2 -fPIC -fvisibility=hidden -shared -std=c11 \
    -Wall -Wextra -Wno-unused-parameter \
    --sysroot="$SYSROOT" \
    -I"$WORK/rtlsdr/include" \
    -L"$WORK/rtlsdr/build/src" \
    -o "$OUT_DIR/libtetherand_sdr.so" \
    "$REPO_ROOT/scripts/sdr_jni/sdr_jni.c" \
    -lrtlsdr -lm -llog

ls -lh "$OUT_DIR/libusb-1.0.so" "$OUT_DIR/librtlsdr.so" "$OUT_DIR/libhackrf.so" "$OUT_DIR/libtetherand_sdr.so"
echo "M7b SDR libs built + staged (libtetherand_sdr.so wired into librtlsdr.so)."
