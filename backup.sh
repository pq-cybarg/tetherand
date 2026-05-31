#!/usr/bin/env bash
# backup.sh — fully local backup of a connected Android device.
#
# Captures everything recoverable from an un-rooted Android 16 device:
#   • All settings (global, secure, system) — for full settings-restore
#   • All installed APKs (user + system) — for app reinstall
#   • Per-app data via `adb backup` for apps that allow it (best-effort —
#     most privacy-focused apps deliberately disable this)
#   • User storage: /sdcard (Pictures, DCIM, Movies, Music, Documents,
#     Download), with caches excluded
#   • Device fingerprint, build props, package list, permission grants
#   • SHA-256 manifest of every file
#
# Output: backups/<UTC-timestamp>/  with optional AES-256-CBC encryption.
#
# Usage:
#   ./backup.sh                       # full encrypted backup, prompts for passphrase
#   ./backup.sh --light               # settings + apk list + metadata only
#   ./backup.sh --media-only          # just /sdcard media (no APKs, no data)
#   ./backup.sh --to /path/to/dir     # backup to a different parent directory
#   ./backup.sh --no-encrypt          # plaintext tarball (NOT recommended)
#   ./backup.sh --passphrase-file F   # read passphrase from F instead of prompting
#
# Does NOT capture (technically impossible on un-rooted Android 16):
#   • Solana Seed Vault keys (hardware-backed; this is intentional — move
#     them off-device manually before 5364C13D via the official export flow).
#   • Signal / WhatsApp / banking app private data (those apps refuse
#     adb backup by design).
#   • Hardware keystore-backed keys.
# For those, follow each app's own backup procedure.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

mode="full"
parent_dir="$HERE/backups"
encrypt=1
passfile=""
while (( $# )); do
  case "$1" in
    --light)            mode="light";     shift ;;
    --media-only)       mode="media";     shift ;;
    --to)               parent_dir="$2";  shift 2 ;;
    --no-encrypt)       encrypt=0;        shift ;;
    --passphrase-file)  passfile="$2";    shift 2 ;;
    -h|--help)          sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                  echo "error: unknown arg $1" >&2; exit 1 ;;
  esac
done

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'
c_bld=$'\033[1m';  c_rst=$'\033[0m'
say()  { printf "%s==>%s %s\n" "$c_cyn" "$c_rst" "$*"; }
ok()   { printf "%s  ✓%s %s\n" "$c_grn" "$c_rst" "$*"; }
warn() { printf "%s  !%s %s\n" "$c_yel" "$c_rst" "$*"; }
err()  { printf "%s  ✗%s %s\n" "$c_red" "$c_rst" "$*"; }

# Detect device.
SERIAL="$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
if [[ -z "$SERIAL" ]]; then
  err "No Android device in 'device' state."; "$ADB" devices >&2; exit 1
fi
MODEL=$("$ADB" -s "$SERIAL" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
ANDROID=$("$ADB" -s "$SERIAL" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')

# Output dir.
TS="$(date -u +%Y%m%d-%H%M%SZ)"
OUT="$parent_dir/$MODEL-$SERIAL-$TS"
mkdir -p "$OUT"

# Banner.
printf "%s\n" "$c_bld"
cat <<BANNER
   ┌─────────────────────────────────────────────────────────────┐
   │  Local Android backup                                        │
   │  Device : $MODEL  ($SERIAL)
   │  Android: $ANDROID
   │  Mode   : $mode
   │  Out    : $OUT
   │  Encrypt: $( ((encrypt)) && echo "yes (AES-256-CBC, PBKDF2)" || echo "NO (plaintext)" )
   └─────────────────────────────────────────────────────────────┘
BANNER
printf "%s\n" "$c_rst"

###############################################################################
# 1. Metadata
###############################################################################
say "Capturing device metadata"
{
  printf 'serial\t%s\n'   "$SERIAL"
  printf 'model\t%s\n'    "$MODEL"
  printf 'android\t%s\n'  "$ANDROID"
  printf 'timestamp\t%s\n' "$TS"
  printf 'mode\t%s\n'     "$mode"
  printf 'fingerprint\t%s\n' "$("$ADB" -s "$SERIAL" shell getprop ro.build.fingerprint | tr -d '\r')"
  printf 'bootloader\t%s\n' "$("$ADB" -s "$SERIAL" shell getprop ro.bootloader | tr -d '\r')"
  printf 'baseband\t%s\n' "$("$ADB" -s "$SERIAL" shell getprop gsm.version.baseband | tr -d '\r')"
} > "$OUT/manifest.tsv"
"$ADB" -s "$SERIAL" shell getprop > "$OUT/getprop.txt"
ok "metadata captured"

###############################################################################
# 2. Settings (always, even in media-only mode — they're tiny and critical)
###############################################################################
say "Capturing settings (global / secure / system)"
mkdir -p "$OUT/settings"
"$ADB" -s "$SERIAL" shell settings list global > "$OUT/settings/global.txt"
"$ADB" -s "$SERIAL" shell settings list secure > "$OUT/settings/secure.txt"
"$ADB" -s "$SERIAL" shell settings list system > "$OUT/settings/system.txt"
ok "$(wc -l < "$OUT/settings/global.txt" | tr -d ' ') global, $(wc -l < "$OUT/settings/secure.txt" | tr -d ' ') secure, $(wc -l < "$OUT/settings/system.txt" | tr -d ' ') system entries"

###############################################################################
# 3. Package list (always)
###############################################################################
say "Capturing package list + signing fingerprints"
mkdir -p "$OUT/packages"
"$ADB" -s "$SERIAL" shell pm list packages -f -i -U > "$OUT/packages/list.txt"
"$ADB" -s "$SERIAL" shell pm list packages -d     > "$OUT/packages/disabled.txt"
"$ADB" -s "$SERIAL" shell pm list packages -3     > "$OUT/packages/user-installed.txt"
"$ADB" -s "$SERIAL" shell pm list packages -s     > "$OUT/packages/system.txt"
: > "$OUT/packages/sigs.tsv"
"$ADB" -s "$SERIAL" shell pm list packages | sed 's/^package://' | tr -d '\r' | sort -u | while read -r pkg; do
  [[ -n "$pkg" ]] || continue
  info=$("$ADB" -s "$SERIAL" shell dumpsys package "$pkg" 2>/dev/null)
  ver=$(echo "$info" | grep -oE 'versionName=[^ ]+' | head -1 | sed 's/versionName=//' | tr -d '\r')
  sig=$(echo "$info" | grep -oE 'signatures:\[[^]]+\]' | head -1 | sed 's/signatures:\[//; s/\]$//' | tr -d '\r ')
  printf "%s\t%s\t%s\n" "$pkg" "${ver:-?}" "${sig:-MISSING}" >> "$OUT/packages/sigs.tsv"
done
ok "$(wc -l < "$OUT/packages/list.txt" | tr -d ' ') packages catalogued"

###############################################################################
# 4. Permission grants (always)
###############################################################################
say "Snapshotting permission grants"
"$ADB" -s "$SERIAL" shell dumpsys package | awk '
  /^Packages:/ {in_pkgs=1}
  in_pkgs && /^  Package \[/ {pkg=$0; sub(/^  Package \[/,"",pkg); sub(/\].*$/,"",pkg)}
  in_pkgs && /granted=true/ {print pkg "\t" $0}
' > "$OUT/packages/grants.tsv" 2>/dev/null || true
ok "$(wc -l < "$OUT/packages/grants.tsv" | tr -d ' ') permission grants snapshotted"

###############################################################################
# 5. Mode-gated work
###############################################################################
if [[ "$mode" == "full" ]]; then
  ###############################################################################
  # 5a. Pull APKs
  ###############################################################################
  say "Pulling APKs (this is the biggest step; expect minutes for many apps)"
  mkdir -p "$OUT/apks"
  count=0
  total=$(wc -l < "$OUT/packages/list.txt" | tr -d ' ')
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # Line format: package:/data/app/.../base.apk=com.example
    path=$(echo "$line" | sed 's/^package://; s/=.*$//')
    pkg=$(echo  "$line" | sed 's/.*=//')
    safe="${pkg//[^a-zA-Z0-9._-]/_}"
    count=$((count+1))
    printf "\r   [%4d/%4d] %-48.48s" "$count" "$total" "$pkg"
    "$ADB" -s "$SERIAL" pull "$path" "$OUT/apks/${safe}.apk" >/dev/null 2>&1 || true
  done < "$OUT/packages/list.txt"
  printf "\r%80s\r" ""
  ok "pulled $(ls "$OUT/apks" 2>/dev/null | wc -l | tr -d ' ') APKs"

  ###############################################################################
  # 5b. Per-app `adb backup` (best-effort — most modern apps reject this)
  ###############################################################################
  say "Per-app adb backup (best-effort)"
  mkdir -p "$OUT/app-data"
  warn "On Android 12+, most apps refuse adb backup. This captures what's possible."
  warn "Confirm the backup prompt on the device when it appears (within 5 minutes)."
  AB_FILE="$OUT/app-data/adb-backup.ab"
  # Run adb backup in the background with a hard timeout. adb backup is interactive
  # on the device side (user must tap "Back up my data"); if the user ignores the
  # prompt we don't want this script to hang forever.
  "$ADB" -s "$SERIAL" backup -nosystem -apk -shared -all -f "$AB_FILE" >/dev/null 2>&1 &
  bk_pid=$!
  ( sleep 300 && kill "$bk_pid" 2>/dev/null || true ) &
  watcher_pid=$!
  wait "$bk_pid" 2>/dev/null || true
  kill "$watcher_pid" 2>/dev/null || true
  if [[ -s "$AB_FILE" ]] && [[ $(stat -f %z "$AB_FILE" 2>/dev/null || stat -c %s "$AB_FILE") -gt 1024 ]]; then
    ok "adb-backup.ab: $(du -h "$AB_FILE" | awk '{print $1}')"
  else
    warn "adb backup produced no useful data (expected on Android 12+)"
    rm -f "$AB_FILE"
  fi

  ###############################################################################
  # 5c. Pull /sdcard media (selective)
  ###############################################################################
  say "Pulling user storage (Pictures, DCIM, Movies, Music, Documents, Download)"
  mkdir -p "$OUT/sdcard"
  for d in DCIM Pictures Movies Music Documents Download Audiobooks Podcasts Ringtones Notifications Alarms Recordings; do
    if "$ADB" -s "$SERIAL" shell test -d "/sdcard/$d" 2>/dev/null; then
      printf "   pulling /sdcard/%s ... " "$d"
      "$ADB" -s "$SERIAL" pull -a "/sdcard/$d" "$OUT/sdcard/" >/dev/null 2>&1 \
        && echo "ok" \
        || echo "(empty or denied)"
    fi
  done
  total_bytes=$(du -sh "$OUT/sdcard" 2>/dev/null | awk '{print $1}')
  ok "user storage: $total_bytes"

elif [[ "$mode" == "media" ]]; then
  say "Pulling user storage only"
  mkdir -p "$OUT/sdcard"
  for d in DCIM Pictures Movies Music Documents Download; do
    "$ADB" -s "$SERIAL" shell test -d "/sdcard/$d" 2>/dev/null \
      && "$ADB" -s "$SERIAL" pull -a "/sdcard/$d" "$OUT/sdcard/" >/dev/null 2>&1 || true
  done
  ok "media: $(du -sh "$OUT/sdcard" 2>/dev/null | awk '{print $1}')"
fi

###############################################################################
# 6. Compute SHA-256 manifest of everything we backed up
###############################################################################
say "Computing SHA-256 manifest"
( cd "$OUT" && find . -type f ! -name 'sha256.tsv' -print0 \
  | xargs -0 shasum -a 256 \
  | sed 's|  \./|  |' \
  > sha256.tsv )
ok "$(wc -l < "$OUT/sha256.tsv" | tr -d ' ') files in manifest"

###############################################################################
# 7. Tar + (optional) encrypt
###############################################################################
ARCHIVE="$parent_dir/$MODEL-$SERIAL-$TS.tar.gz"
say "Archiving"
tar -C "$parent_dir" -czf "$ARCHIVE" "$(basename "$OUT")"
ARCH_SIZE=$(du -sh "$ARCHIVE" | awk '{print $1}')
ok "archive: $ARCHIVE  ($ARCH_SIZE)"

if (( encrypt )); then
  say "Encrypting with AES-256-CBC + PBKDF2"
  ENC="$ARCHIVE.enc"
  if [[ -n "$passfile" && -s "$passfile" ]]; then
    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
      -in "$ARCHIVE" -out "$ENC" -pass "file:$passfile"
  else
    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
      -in "$ARCHIVE" -out "$ENC"
  fi
  rm -f "$ARCHIVE"
  ARCHIVE="$ENC"
  ok "encrypted: $ARCHIVE  ($(du -sh "$ARCHIVE" | awk '{print $1}'))"
fi

# Clean up the unencrypted dir if we encrypted (the archive supersedes it).
if (( encrypt )); then
  rm -rf "$OUT"
fi

printf "\n%sBackup complete.%s\n" "$c_bld" "$c_rst"
printf "  Restore with: ./restore.sh %s\n" "$ARCHIVE"
