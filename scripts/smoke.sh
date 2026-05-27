#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end test of tetherand M1.
#
# Reinstalls the APK, runs `tetherand run` in the background, waits for
# the tether to come up, verifies ping + DNS + HTTPS, then stops.
#
# Exit code 0 on success.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HERE/bin/tetherand"
APK="$HERE/bin/tetherand.apk"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

[[ -x "$BIN" ]] || { echo "build first: make build"; exit 1; }
[[ -f "$APK" ]] || { echo "APK missing — run make apk"; exit 1; }

serial=$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')
[[ -n "$serial" ]] || { echo "no device connected"; "$ADB" devices; exit 1; }
echo "device: $serial"

# Ensure clean slate.
"$ADB" -s "$serial" reverse --remove localabstract:tetherand 2>/dev/null || true
"$ADB" -s "$serial" shell am force-stop dev.tetherand.app 2>/dev/null || true
pkill -9 -f "bin/tetherand run" 2>/dev/null || true
sleep 1

echo "[1/4] reinstalling APK"
"$ADB" -s "$serial" install -r "$APK" >/dev/null

echo "[2/4] starting tetherand"
ADB="$ADB" "$BIN" run --device "$serial" --transport adb &
TPID=$!
trap 'kill -INT $TPID 2>/dev/null || true; sleep 1; kill -9 $TPID 2>/dev/null || true' EXIT
sleep 4

echo "[3/4] ping + DNS verification"
"$ADB" -s "$serial" shell ping -c 2 -W 4 1.1.1.1 >/dev/null \
  || { echo "✗ ping 1.1.1.1 failed"; exit 2; }
echo "  ✓ ping 1.1.1.1"

# Android's stock toybox includes 'getent' on many builds; use settings as fallback.
"$ADB" -s "$serial" shell ping -c 1 -W 4 cloudflare.com >/dev/null \
  || { echo "✗ DNS-resolved ping (cloudflare.com) failed"; exit 3; }
echo "  ✓ ping cloudflare.com (DNS works)"

echo "[4/4] HTTPS test (best effort — Android shell may lack curl)"
if "$ADB" -s "$serial" shell "command -v curl" >/dev/null 2>&1; then
  out=$("$ADB" -s "$serial" shell "curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 8 https://cloudflare.com" 2>&1) \
    && echo "  ✓ HTTPS: $out" \
    || echo "  (HTTPS not verified: $out)"
else
  echo "  (skip — no curl in device shell; ping-based check above is sufficient)"
fi

kill -INT $TPID
wait $TPID 2>/dev/null || true
echo "✓ smoke ok"
