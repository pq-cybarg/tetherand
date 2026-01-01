#!/usr/bin/env bash
# Build + sign a release APK.
#
# Uses the debug keystore by default (so it installs alongside the
# debug build with no key dance). For a production release you would
# generate a real keystore with `keytool -genkeypair` and point this
# script at it via the KEYSTORE / KS_PASS / KEY_ALIAS / KEY_PASS env
# vars below.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEYSTORE="${KEYSTORE:-$HOME/.android/debug.keystore}"
KS_PASS="${KS_PASS:-android}"
KEY_ALIAS="${KEY_ALIAS:-androiddebugkey}"
KEY_PASS="${KEY_PASS:-android}"

[ -f "$KEYSTORE" ] || { echo "no keystore at $KEYSTORE — generate one with keytool first"; exit 1; }

# Opsec gate: refuse to sign unless the keystore DN matches an allow-list
# of approved public identities. Once a production APK ships with a given
# DN the cert is permanent — Google Play rejects updates signed by a
# different key. So fail loudly here rather than silently shipping a real
# name in every release. The allow-list lives in an out-of-repo file
# (~/.tetherand-signing-allow), one DN per line, so the actual strings
# we check against never enter the repo.
#
# Recommended keystore generation (do this BEFORE running this script):
#   keytool -genkeypair -alias <your-alias> -keystore <your.jks> \
#       -keyalg RSA -keysize 4096 -validity 36500 \
#       -dname "CN=<published-handle>, O=<published-handle>, C=US"
ALLOW="${TETHERAND_SIGNING_ALLOW:-$HOME/.tetherand-signing-allow}"
SUBJECT="$(keytool -list -v -keystore "$KEYSTORE" -storepass "$KS_PASS" \
            -alias "$KEY_ALIAS" 2>/dev/null | awk -F': ' '/^Owner:/ {print $2; exit}')"
if [ -z "$SUBJECT" ]; then
    echo "REFUSING TO SIGN — could not read keystore DN."
    exit 1
fi
# Always allow the stock debug DN (well-known, no PII).
DEBUG_DN="C=US, O=Android, CN=Android Debug"
if [ "$SUBJECT" = "$DEBUG_DN" ]; then
    echo "Keystore subject: $SUBJECT (stock debug — OK)"
elif [ -f "$ALLOW" ] && grep -Fxq "$SUBJECT" "$ALLOW"; then
    echo "Keystore subject: $SUBJECT (in allow-list)"
else
    echo "REFUSING TO SIGN — keystore DN not in allow-list."
    echo "DN under inspection (sha256): $(printf '%s' "$SUBJECT" | shasum -a 256 | awk '{print $1}')"
    echo "If you've confirmed this DN carries no PII, append it to $ALLOW:"
    echo "    echo \"<the DN exactly as keytool printed it>\" >> \"$ALLOW\""
    exit 1
fi

cd "$REPO/android"
./gradlew :app:assembleRelease

SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
APKSIGNER=$(ls -1 "$SDK"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1)
ZIPALIGN=$(ls -1 "$SDK"/build-tools/*/zipalign 2>/dev/null | sort -V | tail -1)
[ -x "$APKSIGNER" ] || { echo "apksigner not found in $SDK/build-tools"; exit 1; }
[ -x "$ZIPALIGN" ]  || { echo "zipalign not found in $SDK/build-tools"; exit 1; }

UNSIGNED="$REPO/android/app/build/outputs/apk/release/app-release-unsigned.apk"
[ -f "$UNSIGNED" ] || UNSIGNED="$REPO/android/app/build/outputs/apk/release/app-release.apk"
[ -f "$UNSIGNED" ] || { echo "no release APK output"; exit 1; }

ALIGNED="$REPO/bin/tetherand-release-aligned.apk"
SIGNED="$REPO/bin/tetherand-release.apk"
"$ZIPALIGN" -p 4 "$UNSIGNED" "$ALIGNED"
"$APKSIGNER" sign \
    --ks "$KEYSTORE" --ks-pass "pass:$KS_PASS" \
    --ks-key-alias "$KEY_ALIAS" --key-pass "pass:$KEY_PASS" \
    --out "$SIGNED" "$ALIGNED"
"$APKSIGNER" verify --print-certs "$SIGNED" | head -10
rm -f "$ALIGNED"

ls -lh "$SIGNED"
echo "Release APK: $SIGNED"

# Emit SHA-256 + SHA3-256 sidecars + SHASUMS.txt index so downstream
# verifiers can confirm the artefact without trusting the channel.
"$REPO/scripts/hash-artifacts.sh"
