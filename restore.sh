#!/usr/bin/env bash
# restore.sh — restore a connected Android device from a local backup.sh archive.
#
# Restores:
#   • Settings (global, secure, system) — overlay-style, with a pre-restore
#     snapshot saved so the restore itself is reversible.
#   • APKs — reinstalls user-installed apps. (System apps are not reinstalled;
#     they're updated by the OS.)
#   • User storage — pushes /sdcard subdirectories back.
#   • Per-app data — if the original backup contains an adb-backup.ab,
#     `adb restore` it (requires confirmation on device).
#
# Does NOT restore:
#   • Hardware keystore-backed keys (unrecoverable from a non-root backup).
#   • App private data for apps that refused adb backup at backup time.
#   • Solana Seed Vault state (intentional — hardware-backed).
#
# Usage:
#   ./restore.sh                              # list backups and prompt to pick one
#   ./restore.sh <archive-path>               # restore a specific archive
#   ./restore.sh <archive> --settings-only    # just settings (fastest, lowest-risk)
#   ./restore.sh <archive> --apks-only        # just reinstall the APKs
#   ./restore.sh <archive> --media-only       # just push /sdcard back
#   ./restore.sh <archive> --no-prompt        # skip per-step y/N (DANGEROUS)
#   ./restore.sh <archive> --passphrase-file F
#   ./restore.sh --undo                       # revert to the pre-restore snapshot

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

archive=""
mode="all"
prompt=1
passfile=""
do_undo=0
while (( $# )); do
  case "$1" in
    --settings-only)    mode="settings";  shift ;;
    --apks-only)        mode="apks";      shift ;;
    --media-only)       mode="media";     shift ;;
    --no-prompt)        prompt=0;         shift ;;
    --undo)             do_undo=1;        shift ;;
    --passphrase-file)  passfile="$2";    shift 2 ;;
    -h|--help)
      sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "error: unknown flag $1" >&2; exit 1 ;;
    *)  archive="$1"; shift ;;
  esac
done

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'
c_bld=$'\033[1m';  c_rst=$'\033[0m'
say()  { printf "%s==>%s %s\n" "$c_cyn" "$c_rst" "$*"; }
ok()   { printf "%s  ✓%s %s\n" "$c_grn" "$c_rst" "$*"; }
warn() { printf "%s  !%s %s\n" "$c_yel" "$c_rst" "$*"; }
err()  { printf "%s  ✗%s %s\n" "$c_red" "$c_rst" "$*"; }

confirm() {
  (( prompt )) || return 0
  local q="$1" default="${2:-n}" yn
  read -r -p "$(printf "%s? [%s] " "$q" "$default")" yn
  yn="${yn:-$default}"; [[ "${yn,,}" == y* ]]
}

require_device() {
  SERIAL="$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
  [[ -n "$SERIAL" ]] || { err "No Android device in 'device' state."; "$ADB" devices >&2; exit 1; }
  MODEL=$("$ADB" -s "$SERIAL" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
}

###############################################################################
# Undo path
###############################################################################
if (( do_undo )); then
  require_device
  UNDO_DIR="$HERE/backups/.pre-restore-snapshot"
  [[ -d "$UNDO_DIR" ]] || { err "No pre-restore snapshot at $UNDO_DIR — nothing to undo."; exit 1; }
  say "Reverting to pre-restore snapshot from $UNDO_DIR"
  for scope in global secure system; do
    [[ -s "$UNDO_DIR/settings/$scope.txt" ]] || continue
    say "Reverting Settings.$scope from snapshot"
    while IFS='=' read -r key val; do
      [[ -z "$key" ]] && continue
      "$ADB" -s "$SERIAL" shell settings put "$scope" "$key" "$val" >/dev/null 2>&1 || true
    done < "$UNDO_DIR/settings/$scope.txt"
  done
  ok "Pre-restore settings restored. App reinstalls and file pushes are not reverted."
  exit 0
fi

###############################################################################
# Find/select archive
###############################################################################
if [[ -z "$archive" ]]; then
  say "Available backups in $HERE/backups:"
  mapfile -t backups < <(ls -1t "$HERE/backups"/*.tar.gz "$HERE/backups"/*.tar.gz.enc 2>/dev/null || true)
  if (( ${#backups[@]} == 0 )); then
    err "No backups found. Run ./backup.sh first."; exit 1
  fi
  for i in "${!backups[@]}"; do
    sz=$(du -h "${backups[$i]}" | awk '{print $1}')
    printf "   [%d] %s  (%s)\n" "$((i+1))" "$(basename "${backups[$i]}")" "$sz"
  done
  read -r -p "Pick: " idx
  archive="${backups[$((idx-1))]}"
fi
[[ -f "$archive" ]] || { err "Archive not found: $archive"; exit 1; }

###############################################################################
# Decrypt + extract
###############################################################################
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$archive" == *.enc ]]; then
  say "Decrypting (AES-256-CBC, PBKDF2)"
  if [[ -n "$passfile" && -s "$passfile" ]]; then
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$archive" \
      -out "$WORK/backup.tar.gz" -pass "file:$passfile"
  else
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$archive" \
      -out "$WORK/backup.tar.gz"
  fi
  tarball="$WORK/backup.tar.gz"
else
  tarball="$archive"
fi

say "Extracting archive"
tar -C "$WORK" -xzf "$tarball"
SRC="$(ls -1d "$WORK"/*/ | head -1)"
SRC="${SRC%/}"
[[ -d "$SRC" ]] || { err "Could not find backup root inside archive"; exit 1; }
ok "extracted: $SRC"

###############################################################################
# Verify manifest
###############################################################################
if [[ -s "$SRC/sha256.tsv" ]]; then
  say "Verifying SHA-256 manifest ($(wc -l < "$SRC/sha256.tsv" | tr -d ' ') files)"
  ( cd "$SRC" && shasum -a 256 -c sha256.tsv 2>&1 | grep -v ': OK$' | head -20 ) \
    && ok "manifest OK" || warn "some files failed manifest check (see above)"
fi

###############################################################################
# Device + pre-restore snapshot
###############################################################################
require_device
warn "Restoring to: $MODEL ($SERIAL)"
warn "Backup source: $(grep '^model' "$SRC/manifest.tsv" | cut -f2) ($(grep '^serial' "$SRC/manifest.tsv" | cut -f2))"

if ! grep -q "^serial.$SERIAL" "$SRC/manifest.tsv"; then
  warn "WARNING: serial mismatch — you are restoring a backup taken from a DIFFERENT device."
  warn "This is usually wrong. Settings/apps from another device may misbehave."
  confirm "Continue anyway" n || { err "Aborting."; exit 1; }
fi

UNDO="$HERE/backups/.pre-restore-snapshot"
say "Capturing pre-restore snapshot to $UNDO (for ./restore.sh --undo)"
rm -rf "$UNDO"; mkdir -p "$UNDO/settings"
"$ADB" -s "$SERIAL" shell settings list global > "$UNDO/settings/global.txt"
"$ADB" -s "$SERIAL" shell settings list secure > "$UNDO/settings/secure.txt"
"$ADB" -s "$SERIAL" shell settings list system > "$UNDO/settings/system.txt"
ok "pre-restore snapshot ready"

###############################################################################
# Restore: settings
###############################################################################
restore_settings() {
  for scope in global secure system; do
    [[ -s "$SRC/settings/$scope.txt" ]] || continue
    say "Restoring Settings.$scope"
    local applied=0 skipped=0
    while IFS='=' read -r key val; do
      [[ -z "$key" ]] && continue
      # Skip read-only / system-managed keys that adb cannot write.
      case "$key" in
        device_provisioned|user_setup_complete|android_id) skipped=$((skipped+1)); continue ;;
      esac
      if "$ADB" -s "$SERIAL" shell settings put "$scope" "$key" "$val" >/dev/null 2>&1; then
        applied=$((applied+1))
      else
        skipped=$((skipped+1))
      fi
    done < "$SRC/settings/$scope.txt"
    ok "$scope: $applied applied, $skipped skipped"
  done
}

###############################################################################
# Restore: APKs
###############################################################################
restore_apks() {
  [[ -d "$SRC/apks" ]] || { warn "no apks in backup"; return; }
  say "Reinstalling APKs"
  local total ok_count fail_count
  total=$(ls -1 "$SRC/apks"/*.apk 2>/dev/null | wc -l | tr -d ' ')
  ok_count=0; fail_count=0
  for apk in "$SRC/apks"/*.apk; do
    [[ -f "$apk" ]] || continue
    name=$(basename "$apk" .apk)
    printf "\r   [%d/%d] %-48.48s" $((ok_count+fail_count+1)) "$total" "$name"
    if "$ADB" -s "$SERIAL" install -r -g "$apk" >/dev/null 2>&1; then
      ok_count=$((ok_count+1))
    else
      fail_count=$((fail_count+1))
    fi
  done
  printf "\r%80s\r" ""
  ok "APKs: $ok_count installed, $fail_count failed (system apps usually fail — expected)"
}

###############################################################################
# Restore: media (/sdcard)
###############################################################################
restore_media() {
  [[ -d "$SRC/sdcard" ]] || { warn "no sdcard data in backup"; return; }
  say "Pushing user storage back to /sdcard"
  for d in "$SRC/sdcard"/*/; do
    [[ -d "$d" ]] || continue
    name=$(basename "$d")
    printf "   pushing %s ... " "$name"
    "$ADB" -s "$SERIAL" push "$d" "/sdcard/" >/dev/null 2>&1 && echo "ok" || echo "(partial)"
  done
  ok "user storage pushed"
}

###############################################################################
# Restore: app-data (adb backup)
###############################################################################
restore_appdata() {
  local ab="$SRC/app-data/adb-backup.ab"
  [[ -s "$ab" ]] || return 0
  say "Restoring adb-backup.ab (confirm prompt on device within 2 min)"
  "$ADB" -s "$SERIAL" restore "$ab" &
  pid=$!
  ( sleep 120 && kill "$pid" 2>/dev/null || true ) &
  wait "$pid" 2>/dev/null || true
  ok "adb-restore complete"
}

###############################################################################
# Run
###############################################################################
case "$mode" in
  settings)
    confirm "Restore settings to $MODEL?" y && restore_settings ;;
  apks)
    confirm "Reinstall APKs onto $MODEL?" y && restore_apks ;;
  media)
    confirm "Push /sdcard media onto $MODEL?" y && restore_media ;;
  all)
    confirm "Restore EVERYTHING (settings, APKs, media, app-data) to $MODEL?" y || { err "Aborted."; exit 1; }
    restore_settings
    restore_apks
    restore_media
    restore_appdata
    ;;
esac

printf "\n%sRestore complete.%s\n" "$c_bld" "$c_rst"
printf "  Undo with: ./restore.sh --undo\n"
