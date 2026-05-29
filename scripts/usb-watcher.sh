#!/usr/bin/env bash
# M2 macOS USB watcher.
#
# Polls IOKit (via `system_profiler SPUSBDataType`) for the Solana
# Mobile vendor:product ID, and when the Seeker is attached fires
# `tetherand run --transport adb` in the background. When unplugged the
# child is reaped on the next poll.
#
# This is a deliberately simple polling implementation — IOKit kqueue
# notifications would be more efficient but require an Objective-C
# wrapper. 1s poll is fine for a single-device tether.
#
# Solana Seeker USB IDs (as reported by `lsusb` / IOKit):
#   vendor  = 0x18d1   (Google — Android stock)
#   product = 0x4ee7   (MTP) or 0x4ee2 (MTP+ADB) or 0x2d01 (AOA+ADB)

set -u
LOG=/tmp/tetherand-launcher.log
SEEKER_VENDOR="0x18d1"
SEEKER_PRODUCTS=("0x4ee7" "0x4ee2" "0x2d01" "0x2d00")
INTERVAL=${TETHERAND_USB_POLL_SEC:-1}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/bin/tetherand"
[ -x "$BIN" ] || { echo "$(date) tetherand binary missing at $BIN" >> "$LOG"; exit 1; }

is_attached() {
    system_profiler SPUSBDataType 2>/dev/null \
      | awk -v v="$SEEKER_VENDOR" '
          /Vendor ID:/ { vid = $3 }
          /Product ID:/ { if (vid == v) { found=1 } }
          END { exit(found ? 0 : 1) }'
}

CHILD_PID=
on_term() {
    [ -n "$CHILD_PID" ] && kill -TERM "$CHILD_PID" 2>/dev/null
    exit 0
}
trap on_term TERM INT

echo "$(date) usb-watcher start (poll=${INTERVAL}s)" >> "$LOG"
while :; do
    if is_attached; then
        if [ -z "$CHILD_PID" ] || ! kill -0 "$CHILD_PID" 2>/dev/null; then
            echo "$(date) Seeker attached — starting tetherand run" >> "$LOG"
            "$BIN" run --transport adb >> "$LOG" 2>&1 &
            CHILD_PID=$!
        fi
    else
        if [ -n "$CHILD_PID" ]; then
            echo "$(date) Seeker detached — stopping tetherand (pid $CHILD_PID)" >> "$LOG"
            kill -TERM "$CHILD_PID" 2>/dev/null
            wait "$CHILD_PID" 2>/dev/null
            CHILD_PID=
        fi
    fi
    sleep "$INTERVAL"
done
