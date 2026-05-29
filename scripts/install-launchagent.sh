#!/usr/bin/env bash
# Install the Tetherand LaunchAgent so the Mac auto-starts `tetherand run`
# whenever the Seeker is plugged in.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/Library/LaunchAgents/com.tetherand.launcher.plist"

mkdir -p "$HOME/Library/LaunchAgents"
cp "$HERE/com.tetherand.launcher.plist" "$DEST"
chmod 644 "$DEST"
chmod +x "$HERE/usb-watcher.sh"

launchctl unload "$DEST" 2>/dev/null || true
launchctl load -w "$DEST"
echo "Installed.   launchctl list | grep tetherand"
echo "Logs at /tmp/tetherand-launcher.{log,err}"
echo "Uninstall:   launchctl unload \"$DEST\" && rm \"$DEST\""
