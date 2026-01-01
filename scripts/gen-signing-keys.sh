#!/usr/bin/env bash
# Generate the two AI Guard model-bundle signing keypairs and emit the
# pubkey hex constants ready to paste into
# android/app/src/main/kotlin/dev/tetherand/app/aiguard/runtime/ModelUpdater.kt
#
# Keys produced:
#   keys/aiguard-signer-ecdsa.pem      ECDSA P-256 private key
#   keys/aiguard-signer-ecdsa.pub.der  ECDSA P-256 X.509/SPKI pubkey
#   keys/aiguard-signer-mldsa.pem      ML-DSA-87 private key
#   keys/aiguard-signer-mldsa.pub.der  ML-DSA-87 X.509/SPKI pubkey
#
# Usage:
#   bash scripts/gen-signing-keys.sh           # generate, refuse if exists
#   bash scripts/gen-signing-keys.sh --force   # overwrite existing keys
#
# After running, paste the two hex values printed at the end into the
# `ECDSA_PUBKEY_HEX` and `MLDSA_PUBKEY_HEX` constants in ModelUpdater.kt.
#
# Then keep the .pem files OFFLINE. They sign every manifest. Loss
# of either file = inability to issue updates (which is fine — the
# old shipped APK keeps working). Compromise of either file = an
# attacker can sign one half of the pair, but not both — the hybrid
# verifier rejects single-sig manifests. Compromise of BOTH files is
# total release-channel takeover; rotate via re-keygen + APK reship.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEYS_DIR="$REPO/keys"
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        --help|-h)
            sed -n '2,32p' "$0"
            exit 0 ;;
        *)
            echo "unknown flag: $arg" >&2
            exit 2 ;;
    esac
done

# ---- Preflight: tools + permissions -----------------------------------

command -v openssl >/dev/null || { echo "openssl not on PATH" >&2; exit 1; }

# Need OpenSSL 3.5+ for native ML-DSA-87. Check the version banner.
OSSL_VERSION=$(openssl version | awk '{print $2}')
OSSL_MAJOR=$(echo "$OSSL_VERSION" | cut -d. -f1)
OSSL_MINOR=$(echo "$OSSL_VERSION" | cut -d. -f2)
if [ "$OSSL_MAJOR" -lt 3 ] || { [ "$OSSL_MAJOR" -eq 3 ] && [ "$OSSL_MINOR" -lt 5 ]; }; then
    echo "OpenSSL $OSSL_VERSION lacks ML-DSA-87 (need 3.5+)." >&2
    echo "On macOS: 'brew install openssl@3'; on Linux check your distro for openssl-3.5+." >&2
    exit 1
fi

# Confirm ML-DSA-87 actually probes (some OpenSSL 3.5 builds ship
# without the PQ algorithms unless a separate provider is loaded).
if ! openssl genpkey -algorithm ML-DSA-87 -out /tmp/.tetherand-keygen-probe 2>/dev/null; then
    echo "openssl knows the version but cannot generate ML-DSA-87." >&2
    echo "Your build is missing the PQC algorithms. Reinstall openssl or load a PQC provider." >&2
    rm -f /tmp/.tetherand-keygen-probe
    exit 1
fi
rm -f /tmp/.tetherand-keygen-probe

mkdir -p "$KEYS_DIR"

# ---- Refuse to clobber unless --force ----------------------------------

for f in aiguard-signer-ecdsa.pem aiguard-signer-mldsa.pem \
         aiguard-signer-ecdsa.pub.der aiguard-signer-mldsa.pub.der; do
    if [ -f "$KEYS_DIR/$f" ] && [ "$FORCE" -ne 1 ]; then
        echo "Refusing to overwrite existing $f without --force." >&2
        echo "Rotate intentionally; old in-the-wild APKs trust only the old pubkeys." >&2
        exit 1
    fi
done

# ---- Generate the keypairs --------------------------------------------

echo "Generating ECDSA P-256 keypair…"
openssl ecparam -name prime256v1 -genkey -noout \
    -out "$KEYS_DIR/aiguard-signer-ecdsa.pem"
openssl ec -in  "$KEYS_DIR/aiguard-signer-ecdsa.pem" -pubout \
           -outform DER \
           -out "$KEYS_DIR/aiguard-signer-ecdsa.pub.der" 2>/dev/null
chmod 600 "$KEYS_DIR/aiguard-signer-ecdsa.pem"

echo "Generating ML-DSA-87 keypair (FIPS-204, NIST PQC Level 5)…"
openssl genpkey -algorithm ML-DSA-87 \
    -out "$KEYS_DIR/aiguard-signer-mldsa.pem" 2>/dev/null
openssl pkey -in "$KEYS_DIR/aiguard-signer-mldsa.pem" -pubout \
             -outform DER \
             -out "$KEYS_DIR/aiguard-signer-mldsa.pub.der" 2>/dev/null
chmod 600 "$KEYS_DIR/aiguard-signer-mldsa.pem"

ECDSA_HEX="$(xxd -p -c 99999 "$KEYS_DIR/aiguard-signer-ecdsa.pub.der" | tr -d '\n')"
MLDSA_HEX="$(xxd -p -c 99999 "$KEYS_DIR/aiguard-signer-mldsa.pub.der" | tr -d '\n')"

# ---- Sanity-check key shapes ------------------------------------------

# P-256 SPKI is 91 bytes (182 hex chars). ML-DSA-87 SPKI is 2614
# bytes (5228 hex chars). Tolerate ±4 hex chars for header variants.
[ ${#ECDSA_HEX} -ge 178  ] && [ ${#ECDSA_HEX} -le 186 ]  || { echo "ECDSA pubkey unexpected length: ${#ECDSA_HEX}" >&2; exit 1; }
[ ${#MLDSA_HEX} -ge 5224 ] && [ ${#MLDSA_HEX} -le 5232 ] || { echo "ML-DSA pubkey unexpected length: ${#MLDSA_HEX}" >&2; exit 1; }

# ---- Report ------------------------------------------------------------

cat <<EOF

  ✓ ECDSA-P256 keypair  → keys/aiguard-signer-ecdsa.{pem,pub.der}
  ✓ ML-DSA-87  keypair  → keys/aiguard-signer-mldsa.{pem,pub.der}

Next: paste the two values below into
  android/app/src/main/kotlin/dev/tetherand/app/aiguard/runtime/ModelUpdater.kt

────────────────────────────────────────────────────────────────────────
ECDSA_PUBKEY_HEX (${#ECDSA_HEX} hex chars):

$ECDSA_HEX

────────────────────────────────────────────────────────────────────────
MLDSA_PUBKEY_HEX (${#MLDSA_HEX} hex chars):

$MLDSA_HEX

────────────────────────────────────────────────────────────────────────

After pasting and re-building the APK, sign manifests with:

  bash scripts/sign-manifest.sh \\
       keys/aiguard-signer-ecdsa.pem \\
       keys/aiguard-signer-mldsa.pem \\
       <your-manifest-body.json> > <output.json>

Keep the two .pem files OFFLINE. Anyone with both can sign your
release-channel — they ARE the release-channel identity. The hybrid
verifier defends against compromise of either ONE key alone.

EOF
