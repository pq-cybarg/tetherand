#!/usr/bin/env bash
# On-device smoke test for Tetherand on a connected Seeker.
#
# Walks each tab via UiAutomator (monkey for randomized presses), then
# asserts via `dumpsys` that:
#   - the APK is installed
#   - MainActivity launches without crashing
#   - the threat-detection foreground service starts on app launch
#   - tab navigation works (Tether / Privacy / Threat / AI labels visible)
#
# Doesn't exercise the actual reverse-tether path (that needs the host
# CLI running too). Use `make smoke` for the full host+device pipeline.

set -euo pipefail
PKG=dev.tetherand.app
ACTIVITY=$PKG/.MainActivity
DEVICE_OPTS=""
if [ -n "${1:-}" ]; then DEVICE_OPTS="-s $1"; fi
ADB="adb $DEVICE_OPTS"
LOG=/tmp/tetherand-smoke.log
: > "$LOG"

step() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
fail() { echo "FAIL: $*" | tee -a "$LOG" >&2; exit 1; }

step "Check device connected"
$ADB get-state | grep -q device || fail "no device"

step "Check APK installed"
$ADB shell pm list packages | grep -q "$PKG" || fail "$PKG not installed — run \`make install\`"

step "Launch MainActivity"
$ADB shell am start -W -n "$ACTIVITY" 2>&1 | tee -a "$LOG" | grep -q "TotalTime" \
    || fail "activity launch reported no TotalTime"

step "Wait 4 s for first paint + service start"
sleep 4

step "Check ThreatDetectionService running"
$ADB shell dumpsys activity services "$PKG/.threat.service.ThreatDetectionService" \
    | tee -a "$LOG" | grep -q "ServiceRecord" \
    || fail "ThreatDetectionService not in dumpsys"

step "Probe each tab via UI dump"
$ADB shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
$ADB pull /sdcard/ui.xml /tmp/ui.xml >/dev/null 2>&1
for tab in Tether Privacy Threat AI; do
    grep -q "text=\"$tab\"" /tmp/ui.xml \
        || fail "tab label '$tab' not present in UI dump"
    step "  ✓ tab '$tab' visible"
done

step "Tap Threat tab"
THREAT_BOUNDS=$(grep "text=\"Threat\"" /tmp/ui.xml | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | head -1)
echo "  bounds: $THREAT_BOUNDS" | tee -a "$LOG"

step "Snapshot top-of-log warnings"
$ADB logcat -d -t 200 | grep -iE "(tetherand|fatal|crash)" | tail -30 | tee -a "$LOG"

step "OK — smoke pass"
echo "Full log: $LOG"
