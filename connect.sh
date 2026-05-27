#!/usr/bin/env bash
# Reverse-tether an Android device through this Mac's network connection.
#
# Uses upstream Gnirehtet (Genymobile, GPL-3) as a stopgap while the
# custom multi-transport APK is being built. USB-only.
#
# Usage:
#   ./connect.sh                  # auto-detect single connected device
#   ./connect.sh <serial>         # target a specific device serial
#   ./connect.sh --stop [serial]  # stop the VPN client on the device
#   ./connect.sh --reinstall      # force-reinstall the APK then run
#   ./connect.sh --dns 1.1.1.1    # override DNS (default: 8.8.8.8)
#
# Press Ctrl+C to stop the relay and disable reverse tethering.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELAY="$HERE/bin/gnirehtet-relay"
APK="$HERE/bin/gnirehtet.apk"
ADB="${ADB:-$(command -v adb || true)}"

if [[ -z "$ADB" ]]; then
  # Fall back to Android Studio's bundled adb if not on PATH.
  if [[ -x "$HOME/Library/Android/sdk/platform-tools/adb" ]]; then
    ADB="$HOME/Library/Android/sdk/platform-tools/adb"
  else
    echo "error: adb not found. Install platform-tools or set ADB=/path/to/adb." >&2
    exit 1
  fi
fi
export ADB

[[ -x "$RELAY" ]] || { echo "error: relay binary missing at $RELAY" >&2; exit 1; }
[[ -f "$APK"   ]] || { echo "error: gnirehtet.apk missing at $APK"   >&2; exit 1; }

cd "$HERE/bin"  # relay finds gnirehtet.apk in CWD

# Parse flags.
serial=""
mode="run"
dns=""
reinstall=0
while (( $# )); do
  case "$1" in
    --stop)      mode="stop"; shift ;;
    --reinstall) reinstall=1; shift ;;
    --dns)       dns="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "error: unknown flag $1" >&2; exit 1 ;;
    *)
      if [[ -z "$serial" ]]; then serial="$1"; else
        echo "error: unexpected argument $1" >&2; exit 1
      fi
      shift
      ;;
  esac
done

# Auto-detect serial if not given.
if [[ -z "$serial" ]]; then
  mapfile -t devices < <("$ADB" devices | awk 'NR>1 && $2=="device" {print $1}')
  if   (( ${#devices[@]} == 0 )); then
    echo "error: no Android devices in 'device' state. Is USB debugging on?" >&2
    "$ADB" devices >&2
    exit 1
  elif (( ${#devices[@]} == 1 )); then
    serial="${devices[0]}"
  else
    echo "error: multiple devices connected. Specify a serial:" >&2
    printf '  %s\n' "${devices[@]}" >&2
    exit 1
  fi
fi

model="$("$ADB" -s "$serial" shell getprop ro.product.model 2>/dev/null | tr -d '\r')"

# Prefer the custom Tetherand binary + APK from M1 once they exist;
# fall back to the upstream Gnirehtet stopgap. Both paths are functionally
# equivalent over USB.
if [[ -x "$HERE/bin/tetherand" && -f "$HERE/bin/tetherand.apk" ]]; then
  if [[ "$mode" == "stop" ]]; then
    echo ">> stopping tetherand on $serial ($model)"
    # `tetherand` has no explicit `stop` subcommand in M1 (Ctrl+C handles it).
    # Use adb to fire the STOP intent the same way Ctrl+C would.
    exec "$ADB" -s "$serial" shell am start -a dev.tetherand.app.STOP -n dev.tetherand.app/.TetherandActivity
  fi
  if (( reinstall )); then
    echo ">> reinstalling tetherand APK on $serial ($model)"
    "$HERE/bin/tetherand" reinstall --device "$serial"
  fi
  echo ">> reverse-tethering $serial ($model) via USB (tetherand M1)"
  echo "   relay: $HERE/bin/tetherand"
  echo "   apk:   $HERE/bin/tetherand.apk"
  echo "   ctrl-c to disconnect"
  echo
  exec "$HERE/bin/tetherand" run --device "$serial" --transport adb
fi

# --- fallback: upstream Gnirehtet stopgap ---

if [[ "$mode" == "stop" ]]; then
  echo ">> stopping reverse tether on $serial ($model)"
  exec "$RELAY" stop "$serial"
fi

if (( reinstall )); then
  echo ">> reinstalling gnirehtet on $serial ($model)"
  "$RELAY" reinstall "$serial"
fi

echo ">> reverse-tethering $serial ($model) via USB (stopgap: upstream Gnirehtet)"
echo "   relay: $RELAY"
echo "   apk:   $APK"
echo "   dns:   ${dns:-8.8.8.8 (default)}"
echo "   ctrl-c to disconnect"
echo

# `run` installs (if needed), starts the VPN client, starts the relay,
# and stops both on SIGINT.
if [[ -n "$dns" ]]; then
  exec "$RELAY" run "$serial" -d "$dns"
else
  exec "$RELAY" run "$serial"
fi
