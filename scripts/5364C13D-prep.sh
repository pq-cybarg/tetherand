#!/usr/bin/env bash
# 5364C13D-prep.sh — high-value Hardened Mode subset for a connected Android phone.
# Runs over ADB. No root required. Designed for the 5364C13D but generic
# enough for any Android 12+ device.
#
# Usage:
#   ./scripts/5364C13D-prep.sh            # full pre-conference run
#   ./scripts/5364C13D-prep.sh --snapshot # snapshot-only, no settings changes
#   ./scripts/5364C13D-prep.sh --post     # post-conference: snapshot + diff vs pre
#   ./scripts/5364C13D-prep.sh --baseline # 30-min cell environment baseline drive
#   ./scripts/5364C13D-prep.sh --restore  # restore the settings this script changed
#
# Everything destructive is gated behind y/N prompts. Original settings are
# saved to attestation/restore/ so --restore can undo them.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTEST="$HERE/attestation"
RESTORE="$ATTEST/restore"
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"

mode="prep"
case "${1:-}" in
  --snapshot)  mode="snapshot" ;;
  --post)      mode="post"     ;;
  --baseline)  mode="baseline" ;;
  --restore)   mode="restore"  ;;
  -h|--help)
    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  "")          ;;
  *) echo "error: unknown flag $1" >&2; exit 1 ;;
esac

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'
c_bld=$'\033[1m';  c_rst=$'\033[0m'

say()  { printf "%s==>%s %s\n" "$c_cyn" "$c_rst" "$*"; }
ok()   { printf "%s  ✓%s %s\n" "$c_grn" "$c_rst" "$*"; }
warn() { printf "%s  !%s %s\n" "$c_yel" "$c_rst" "$*"; }
err()  { printf "%s  ✗%s %s\n" "$c_red" "$c_rst" "$*"; }

confirm() {
  local prompt="$1" default="${2:-n}" yn
  read -r -p "$(printf "%s? [%s] " "$prompt" "$default")" yn
  yn="${yn:-$default}"
  [[ "${yn,,}" == y* ]]
}

require_device() {
  local serial
  serial="$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
  if [[ -z "$serial" ]]; then
    err "No Android device in 'device' state. Plug in your 5364C13D, accept the USB-debug prompt, and retry."
    "$ADB" devices >&2; exit 1
  fi
  export SERIAL="$serial"
}

mkdir -p "$ATTEST" "$RESTORE"

###############################################################################
# Snapshot
###############################################################################

do_snapshot() {
  local outdir="$1" label="$2"
  mkdir -p "$outdir"
  say "Capturing $label attestation snapshot to $outdir"

  $ADB -s "$SERIAL" shell getprop                                  > "$outdir/getprop.txt"
  $ADB -s "$SERIAL" shell pm list packages -f -i -U                > "$outdir/packages.txt"
  $ADB -s "$SERIAL" shell pm list packages -d                      > "$outdir/disabled.txt"
  $ADB -s "$SERIAL" shell dumpsys package                          > "$outdir/dumpsys_package.txt" 2>/dev/null || true
  $ADB -s "$SERIAL" shell dumpsys device_policy                    > "$outdir/device_policy.txt"  2>/dev/null || true
  $ADB -s "$SERIAL" shell dumpsys accessibility                    > "$outdir/accessibility.txt"  2>/dev/null || true
  $ADB -s "$SERIAL" shell dumpsys deviceidle                       > "$outdir/deviceidle.txt"     2>/dev/null || true
  $ADB -s "$SERIAL" shell settings list global                     > "$outdir/settings_global.txt"
  $ADB -s "$SERIAL" shell settings list secure                     > "$outdir/settings_secure.txt"
  $ADB -s "$SERIAL" shell settings list system                     > "$outdir/settings_system.txt"
  $ADB -s "$SERIAL" shell dumpsys telephony.registry               > "$outdir/telephony.txt"      2>/dev/null || true
  $ADB -s "$SERIAL" shell dumpsys carrier_config                   > "$outdir/carrier_config.txt" 2>/dev/null || true
  $ADB -s "$SERIAL" shell cmd appops query-op ACTIVATE_VPN allow   > "$outdir/vpn_ops.txt"        2>/dev/null || true
  $ADB -s "$SERIAL" shell cmd wifi list-networks                   > "$outdir/wifi_saved.txt"     2>/dev/null || true
  $ADB -s "$SERIAL" shell dumpsys battery                          > "$outdir/battery.txt"
  $ADB -s "$SERIAL" shell dumpsys thermalservice                   > "$outdir/thermal.txt"        2>/dev/null || true
  $ADB -s "$SERIAL" shell dumpsys netstats --full                  > "$outdir/netstats.txt"       2>/dev/null || true
  $ADB -s "$SERIAL" shell ls /system/etc/security/cacerts          > "$outdir/cacerts_system.txt" 2>/dev/null || true
  $ADB -s "$SERIAL" shell ls /data/misc/user/0/cacerts-added       > "$outdir/cacerts_user.txt"   2>/dev/null || true

  # Per-package signing-cert fingerprint. Format on Android:
  #   signatures=PackageSignatures{<hash> version:N, signatures:[<hex>], past signatures:[...]}
  # The bracketed hex uniquely identifies the signer; a change implies tampering.
  mkdir -p "$outdir/sigs"
  : > "$outdir/sigs/all.tsv"
  $ADB -s "$SERIAL" shell pm list packages | sed 's/^package://' | tr -d '\r' | sort -u | while read -r pkg; do
    [[ -n "$pkg" ]] || continue
    sig=$($ADB -s "$SERIAL" shell dumpsys package "$pkg" 2>/dev/null \
      | grep -oE 'signatures:\[[^]]+\]' \
      | head -1 \
      | sed 's/signatures:\[//; s/\]$//' \
      | tr -d '\r ')
    ver=$($ADB -s "$SERIAL" shell dumpsys package "$pkg" 2>/dev/null \
      | grep -oE 'versionName=[^ ]+' \
      | head -1 \
      | sed 's/versionName=//' \
      | tr -d '\r')
    printf "%s\t%s\t%s\n" "$pkg" "${ver:-?}" "${sig:-MISSING}" >> "$outdir/sigs/all.tsv"
  done

  ok "Snapshot complete: $(wc -l < "$outdir/packages.txt" | tr -d ' ') packages, $(wc -l < "$outdir/sigs/all.tsv" | tr -d ' ') signing certs."
}

###############################################################################
# Cell baseline drive
###############################################################################

do_baseline() {
  require_device
  local out="$ATTEST/cell-baseline-$(date +%Y%m%d-%H%M%S).jsonl"
  say "Starting 30-minute cell-environment baseline."
  say "Walk the venue perimeter (or drive around your hotel + the conference area)."
  say "Press Ctrl+C to stop early; data is appended line-by-line so partial runs are fine."
  say "Writing to: $out"
  trap 'echo; ok "Baseline written: $out"; exit 0' INT

  local end=$(( $(date +%s) + 30*60 ))
  while (( $(date +%s) < end )); do
    local ts cell svc batt
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    cell=$($ADB -s "$SERIAL" shell dumpsys telephony.registry 2>/dev/null \
      | grep -E "mCellInfo|mServiceState|mSignalStrength|mDataConnectionState" \
      | tr '\n' ' ' | sed 's/"/\\"/g')
    batt=$($ADB -s "$SERIAL" shell dumpsys battery 2>/dev/null \
      | awk -F': ' '/level|temperature|current/ {gsub(/^ +/,"",$1); printf "%s=%s;", $1, $2}')
    printf '{"ts":"%s","battery":"%s","telephony":"%s"}\n' "$ts" "$batt" "$cell" >> "$out"
    sleep 30
  done
  ok "Baseline complete: $out"
}

###############################################################################
# Diff (post-conference)
###############################################################################

do_diff() {
  local pre="$ATTEST/pre"  post="$ATTEST/post"
  [[ -d "$pre"  ]] || { err "No pre-conference snapshot at $pre. Run without --post first."; exit 1; }
  [[ -d "$post" ]] || { err "No post-conference snapshot at $post."; exit 1; }
  say "Diff: $pre  vs  $post"
  local diff_out="$ATTEST/diff-$(date +%Y%m%d-%H%M%S).txt"
  diff -u --label PRE --label POST "$pre/packages.txt" "$post/packages.txt" \
    > "$diff_out.packages" 2>/dev/null || true
  diff -u --label PRE --label POST "$pre/sigs/all.tsv" "$post/sigs/all.tsv" \
    > "$diff_out.sigs" 2>/dev/null || true
  diff -u --label PRE --label POST "$pre/device_policy.txt" "$post/device_policy.txt" \
    > "$diff_out.devpol" 2>/dev/null || true
  diff -u --label PRE --label POST "$pre/accessibility.txt" "$post/accessibility.txt" \
    > "$diff_out.access" 2>/dev/null || true
  diff -u --label PRE --label POST "$pre/cacerts_user.txt" "$post/cacerts_user.txt" \
    > "$diff_out.cacerts" 2>/dev/null || true
  diff -u --label PRE --label POST "$pre/settings_secure.txt" "$post/settings_secure.txt" \
    > "$diff_out.settings" 2>/dev/null || true
  printf "\n=== Summary ===\n"
  for f in "$diff_out".*; do
    n=$(grep -cE '^[+-][^+-]' "$f" 2>/dev/null || echo 0)
    name=$(basename "$f")
    if (( n > 0 )); then
      err "${name#*.}: $((n/2)) change(s)"
    else
      ok "${name#*.}: no change"
    fi
  done
  ok "Full diffs in: $diff_out.*"
}

###############################################################################
# Restore
###############################################################################

save_setting() {
  local scope="$1" key="$2"  # scope in {global,secure,system}
  local v
  v=$($ADB -s "$SERIAL" shell settings get "$scope" "$key" 2>/dev/null | tr -d '\r')
  printf "%s\t%s\t%s\n" "$scope" "$key" "$v" >> "$RESTORE/settings.tsv"
}

do_restore() {
  require_device
  [[ -f "$RESTORE/settings.tsv" ]] || { err "Nothing to restore (no $RESTORE/settings.tsv)."; exit 1; }
  say "Restoring settings from $RESTORE/settings.tsv"
  while IFS=$'\t' read -r scope key val; do
    [[ -n "$scope" && -n "$key" ]] || continue
    if [[ "$val" == "null" || -z "$val" ]]; then
      $ADB -s "$SERIAL" shell settings delete "$scope" "$key" >/dev/null 2>&1 || true
    else
      $ADB -s "$SERIAL" shell settings put "$scope" "$key" "$val" >/dev/null 2>&1 || true
    fi
    ok "$scope/$key -> $val"
  done < "$RESTORE/settings.tsv"
}

###############################################################################
# Pre-conference run
###############################################################################

do_prep() {
  require_device
  printf "%s\n" "$c_bld"
  cat <<BANNER
   ┌──────────────────────────────────────────────────────────────────┐
   │  5364C13D pre-flight                                                │
   │  Device: $($ADB -s "$SERIAL" shell getprop ro.product.model | tr -d '\r')  ($SERIAL)$(printf '%*s' $((10 - ${#SERIAL})) '')│
   │  This script makes a snapshot, then walks you through hardening. │
   │  Every change is gated. Use --restore to undo.                   │
   └──────────────────────────────────────────────────────────────────┘
BANNER
  printf "%s\n" "$c_rst"

  # 1. Pre snapshot.
  do_snapshot "$ATTEST/pre" "PRE-conference"

  # 2. Wallet warning (Solana-specific but harmless on other devices).
  if $ADB -s "$SERIAL" shell pm list packages | grep -qiE 'solanamobile|com\.solana'; then
    warn "Solana Mobile Stack detected. Before 5364C13D, move primary keys off-device."
    warn "  1. Use Seed Vault to export the recovery phrase to paper (one-time)."
    warn "  2. Transfer balances to a hardware wallet you leave at home."
    warn "  3. After: factory-reset Seed Vault so on-device storage is empty."
    warn "Verifying on-device Seed Vault state is out of scope of this script — do it manually before continuing."
    confirm "I have either migrated keys or am bringing an empty Seed Vault" n \
      || { err "Aborting. Migrate keys before re-running."; exit 1; }
  fi

  # 3. SIM PIN reminder (can't enable programmatically without root).
  warn "Enable a SIM PIN in Settings → Security → SIM card lock now (cannot be set via ADB)."
  confirm "SIM PIN enabled" n || warn "Continuing without SIM PIN — strongly recommended to enable before 5364C13D."

  # 4. Force LTE-only (no 2G/3G fallback).
  if confirm "Force LTE-only (no 2G/3G — kills most IMSI catchers)" y; then
    save_setting global preferred_network_mode
    save_setting global preferred_network_mode1
    # mode 11 = LTE only on most Android telephony.
    $ADB -s "$SERIAL" shell settings put global preferred_network_mode  11 || warn "could not set preferred_network_mode (carrier may override)"
    $ADB -s "$SERIAL" shell settings put global preferred_network_mode1 11 || true
    ok "preferred_network_mode = 11 (LTE only)"
    warn "If your carrier overrides this, open: Settings → Network → Preferred network type → LTE only"
  fi

  # 5. NFC off.
  if confirm "Disable NFC" y; then
    $ADB -s "$SERIAL" shell svc nfc disable && ok "NFC off" || warn "could not disable NFC via svc; do it manually"
  fi

  # 6. Bluetooth off.
  if confirm "Disable Bluetooth" y; then
    $ADB -s "$SERIAL" shell svc bluetooth disable && ok "Bluetooth off" || warn "could not disable BT via svc; do it manually"
  fi

  # 7. Wi-Fi: forget saved networks.
  if confirm "Forget all saved Wi-Fi networks (defeats KARMA)" n; then
    save_setting global wifi_networks_available_notification_on
    $ADB -s "$SERIAL" shell cmd wifi list-networks 2>/dev/null | tail -n +2 | awk '{print $1}' | while read -r id; do
      [[ -z "$id" ]] && continue
      $ADB -s "$SERIAL" shell cmd wifi forget-network "$id" >/dev/null 2>&1 || true
    done
    ok "all saved Wi-Fi networks forgotten"
  fi

  # 8. Wi-Fi off entirely (you'll use cellular through Mullvad).
  if confirm "Disable Wi-Fi entirely (use only cellular through your VPN)" n; then
    $ADB -s "$SERIAL" shell svc wifi disable && ok "Wi-Fi off"
  fi

  # 9. Always-on VPN + lockdown via Mullvad.
  if $ADB -s "$SERIAL" shell pm list packages | grep -q net.mullvad.mullvadvpn; then
    ok "Mullvad VPN installed"
    warn "Configure in Mullvad app: Settings → VPN settings → enable PQ tunnel + multihop"
    warn "                          choose entry NOT in Las Vegas / Nevada"
    warn "Then in Android: Settings → Network → Advanced → VPN → Mullvad → Always-on + Block connections without VPN"
    confirm "Always-on VPN with lockdown enabled in system Settings" n \
      || warn "Set always-on-VPN before 5364C13D. Without lockdown, leaks happen."
  else
    warn "Mullvad not installed. Install it before 5364C13D: https://mullvad.net/en/download/android"
  fi

  # 10. Orbot (Tor) chain.
  if $ADB -s "$SERIAL" shell pm list packages | grep -q org.torproject.android; then
    ok "Orbot installed"
    warn "In Orbot: enable Snowflake bridge (Settings → Bridges → Snowflake)."
  else
    warn "Orbot not installed. Install before 5364C13D for a second-layer Tor option: https://orbot.app"
  fi

  # 11. ADB authorization reminder.
  warn "ADB auth: this Mac is currently authorized to talk to the 5364C13D. At 5364C13D, do not let any other USB host pair."
  warn "  Consider revoking ADB on the phone post-config: Settings → Developer options → Revoke USB debugging authorizations."
  warn "  Then re-authorize ONLY this Mac when you actually need the tether."

  # 12. Permission audit (dangerous permissions to user-installed apps).
  say "Auditing dangerous permission grants for user-installed apps:"
  $ADB -s "$SERIAL" shell pm list packages -3 | sed 's/^package://' | while read -r pkg; do
    [[ -z "$pkg" ]] && continue
    perms=$($ADB -s "$SERIAL" shell dumpsys package "$pkg" 2>/dev/null \
      | awk '/granted=true/ && /permission.(CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_SMS|READ_CONTACTS|READ_PHONE_STATE|BIND_ACCESSIBILITY|BIND_DEVICE_ADMIN)/ {print $0}' \
      | grep -oE 'android\.permission\.[A-Z_]+' | sort -u | tr '\n' ',')
    [[ -n "$perms" ]] && printf "  %s%s%s  %s\n" "$c_yel" "$pkg" "$c_rst" "${perms%,}"
  done
  warn "Review the above. Revoke anything you don't trust at 5364C13D: Settings → Apps → <app> → Permissions."

  # 13. Hardware buy list.
  say "Recommended hardware to bring to 5364C13D:"
  cat <<HW
   • PortaPow USB Data Blocker (\$7)         — defeats juice jacking
   • Faraday pouch (Mission Darkness)       — phone storage when not in use
   • YubiKey 5C NFC (\$55)                   — hardware 2FA + future unlock fallback
   • RTL-SDR v4 + USB-C OTG cable (\$35)     — full Crocodile Hunter SDR mode (later milestone)
   • Throwaway power bank (\$15)             — never plug into untrusted USB
   • Printed paper backup of any seed phrase you absolutely cannot lose
HW

  # 14. OPSEC reminders.
  say "Operational reminders:"
  cat <<OPSEC
   • Use cash for everything inside the convention hall.
   • Do not connect to "5364C13D-Open" or any unencrypted SSID.
   • Do not pick up USB drives, NFC tags, or QR-code-bearing items from vendor floor.
   • Biometric unlock OFF — use PIN/password only. (Compelled biometrics is real.)
   • Phone in Faraday pouch when sleeping.
   • Different SIM if available; throwaway power bank only.
   • Tor → Mullvad → exit, not Mullvad → Tor → exit (chain order matters).
   • Treat the badge as adversarial; don't plug it into anything.
OPSEC

  # 15. Final post-conference instructions.
  printf "\n%sWhen you get home:%s ./scripts/5364C13D-prep.sh --post   # snapshots + diffs vs pre\n" "$c_bld" "$c_rst"
}

###############################################################################
# Dispatch
###############################################################################

case "$mode" in
  prep)     do_prep ;;
  snapshot) require_device; do_snapshot "$ATTEST/snap-$(date +%Y%m%d-%H%M%S)" "ad-hoc" ;;
  post)     require_device; do_snapshot "$ATTEST/post" "POST-conference"; do_diff ;;
  baseline) do_baseline ;;
  restore)  do_restore ;;
esac
