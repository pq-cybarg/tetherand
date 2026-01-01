#!/usr/bin/env bash
# scripts/smoke-chain.sh — manual-with-script end-to-end test of M3 chain.
#
# Run AFTER the milestone is implemented and you're ready to verify on the
# Seeker. Reinstalls the APK, then waits for you to paste a valid WireGuard
# config into the Privacy tab and tap Start chain. Compares the device's
# apparent egress before and after.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

serial=$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')
[[ -n "$serial" ]] || { echo "no device"; exit 1; }

make build
"$ADB" -s "$serial" install -r "$HERE/bin/tetherand.apk"
"$ADB" -s "$serial" shell cmd appops set dev.tetherand.app ACTIVATE_VPN allow

echo "=== device egress BEFORE chain ==="
"$ADB" -s "$serial" shell "ping -c 1 -W 3 1.1.1.1 >/dev/null && echo 'ping 1.1.1.1 ok' || echo 'unreachable'"
echo
echo "Now: open Tetherand, switch to the Privacy tab,"
echo "paste a valid WireGuard config, and tap 'Start chain'."
echo "Press Enter when the chain shows ROUTING."
read -r

echo "=== device egress AFTER chain ==="
"$ADB" -s "$serial" shell "ping -c 1 -W 4 1.1.1.1 >/dev/null && echo 'ping 1.1.1.1 ok (through chain)' || echo 'unreachable'"
"$ADB" -s "$serial" shell "ping -c 1 -W 4 cloudflare.com >/dev/null && echo 'DNS-resolved ping ok' || echo 'DNS failed'"
echo
echo "Verify the apparent egress IP changed: open https://api.ipify.org in the phone browser."
