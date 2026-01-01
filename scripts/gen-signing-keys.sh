#!/usr/bin/env bash
# Generate the FOUR AI Guard model-bundle signing keypairs and emit the
# pubkey hex constants ready to paste into
# android/app/src/main/kotlin/dev/tetherand/app/aiguard/runtime/ModelUpdater.kt
#
# Keys produced (one keypair per cryptographic family):
#   keys/aiguard-signer-p521.{pem,pub.der}    ECDSA P-521 / SHA-512
#                                             (NIST L5 classical, FIPS 186-5)
#   keys/aiguard-signer-ed448.{pem,pub.der}   Ed448 pure-EdDSA
#                                             (non-NIST classical, RFC 8032)
#   keys/aiguard-signer-mldsa.{pem,pub.der}   ML-DSA-87
#                                             (PQ lattice, FIPS 204, NIST L5)
#   keys/aiguard-signer-slhdsa.{pem,pub.der}  SLH-DSA-SHA2-256s
#                                             (PQ hash-based, FIPS 205, NIST L5)
#
# Why four? The ModelUpdater is the only path that hot-loads code-equivalent
# data (LiteRT model files) post-install. A single compromised algorithm
# would be enough to swap a hostile classifier into the device. By insisting
# that EVERY one of four signatures over diverse cryptographic assumptions
# (NIST EC, non-NIST EC, lattice, stateless hash) verifies, no single family
# break — quantum or otherwise — can unlock the channel. This is the
# IETF composite-sigs philosophy taken to its logical conclusion.
#
# Usage:
#   bash scripts/gen-signing-keys.sh           # generate, refuse if exists
#   bash scripts/gen-signing-keys.sh --force   # overwrite existing keys
#
# After running, paste the FOUR hex values printed at the end into the
# `P521_PUBKEY_HEX`, `ED448_PUBKEY_HEX`, `MLDSA_PUBKEY_HEX`, and
# `SLHDSA_PUBKEY_HEX` constants in ModelUpdater.kt.
#
# Then keep the four .pem files OFFLINE. They sign every manifest. Loss
# of any one of them = inability to issue updates (which is fine — the
# old shipped APK keeps working). Compromise of three of four files
# means an attacker can sign three quarters of the wrapper, but not all
# four — the quadruple verifier rejects any manifest missing even one
# signature. Compromise of ALL FOUR files is total release-channel
# takeover; rotate via re-keygen + APK reship.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEYS_DIR="$REPO/keys"
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        --help|-h)
            sed -n '2,50p' "$0"
            exit 0 ;;
        *)
            echo "unknown flag: $arg" >&2
            exit 2 ;;
    esac
done

# ---- Preflight: tools + permissions -----------------------------------

command -v openssl >/dev/null || { echo "openssl not on PATH" >&2; exit 1; }
command -v xxd     >/dev/null || { echo "xxd not on PATH"     >&2; exit 1; }

# Need OpenSSL 3.5+ for native ML-DSA + SLH-DSA. OpenSSL 3.6 is the
# tested floor (ships ML-DSA + SLH-DSA + Ed448 + ECDSA-P521 with no
# external provider plugin required).
OSSL_VERSION=$(openssl version | awk '{print $2}')
OSSL_MAJOR=$(echo "$OSSL_VERSION" | cut -d. -f1)
OSSL_MINOR=$(echo "$OSSL_VERSION" | cut -d. -f2)
if [ "$OSSL_MAJOR" -lt 3 ] || { [ "$OSSL_MAJOR" -eq 3 ] && [ "$OSSL_MINOR" -lt 5 ]; }; then
    echo "OpenSSL $OSSL_VERSION lacks native PQ support (need 3.5+, 3.6+ recommended)." >&2
    echo "On macOS:  brew install openssl@3" >&2
    echo "On Linux:  check your distro for openssl-3.5+ packages, or build from source." >&2
    echo "Alternative: load the liboqs OpenSSL provider for older builds." >&2
    exit 1
fi

# Confirm each algorithm actually probes — some OpenSSL 3.5 builds ship
# without the PQ algorithms unless a separate provider is loaded.
probe() {
    local alg="$1"; local out
    out=$(openssl genpkey -algorithm "$alg" -out /tmp/.tetherand-keygen-probe 2>&1) || {
        echo "openssl cannot generate $alg: $out" >&2
        echo "Your build is missing $alg. Upgrade OpenSSL or load a provider." >&2
        rm -f /tmp/.tetherand-keygen-probe
        exit 1
    }
    rm -f /tmp/.tetherand-keygen-probe
}
probe ED448
probe ML-DSA-87
probe SLH-DSA-SHA2-256s

mkdir -p "$KEYS_DIR"

# ---- Refuse to clobber unless --force ----------------------------------

for f in aiguard-signer-p521.pem    aiguard-signer-p521.pub.der    \
         aiguard-signer-ed448.pem   aiguard-signer-ed448.pub.der   \
         aiguard-signer-mldsa.pem   aiguard-signer-mldsa.pub.der   \
         aiguard-signer-slhdsa.pem  aiguard-signer-slhdsa.pub.der; do
    if [ -f "$KEYS_DIR/$f" ] && [ "$FORCE" -ne 1 ]; then
        echo "Refusing to overwrite existing $f without --force." >&2
        echo "Rotate intentionally; old in-the-wild APKs trust only the old pubkeys." >&2
        exit 1
    fi
done

# ---- Generate the four keypairs ---------------------------------------

echo "Generating ECDSA P-521 keypair (NIST L5 classical, FIPS 186-5)…"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 \
    -out "$KEYS_DIR/aiguard-signer-p521.pem" 2>/dev/null
openssl pkey -in "$KEYS_DIR/aiguard-signer-p521.pem" -pubout \
             -outform DER \
             -out "$KEYS_DIR/aiguard-signer-p521.pub.der" 2>/dev/null
chmod 600 "$KEYS_DIR/aiguard-signer-p521.pem"

echo "Generating Ed448 keypair (non-NIST classical, RFC 8032 ~L4)…"
openssl genpkey -algorithm ED448 \
    -out "$KEYS_DIR/aiguard-signer-ed448.pem" 2>/dev/null
openssl pkey -in "$KEYS_DIR/aiguard-signer-ed448.pem" -pubout \
             -outform DER \
             -out "$KEYS_DIR/aiguard-signer-ed448.pub.der" 2>/dev/null
chmod 600 "$KEYS_DIR/aiguard-signer-ed448.pem"

echo "Generating ML-DSA-87 keypair (FIPS 204 lattice, NIST L5)…"
openssl genpkey -algorithm ML-DSA-87 \
    -out "$KEYS_DIR/aiguard-signer-mldsa.pem" 2>/dev/null
openssl pkey -in "$KEYS_DIR/aiguard-signer-mldsa.pem" -pubout \
             -outform DER \
             -out "$KEYS_DIR/aiguard-signer-mldsa.pub.der" 2>/dev/null
chmod 600 "$KEYS_DIR/aiguard-signer-mldsa.pem"

echo "Generating SLH-DSA-SHA2-256s keypair (FIPS 205 hash-based, NIST L5)…"
openssl genpkey -algorithm SLH-DSA-SHA2-256s \
    -out "$KEYS_DIR/aiguard-signer-slhdsa.pem" 2>/dev/null
openssl pkey -in "$KEYS_DIR/aiguard-signer-slhdsa.pem" -pubout \
             -outform DER \
             -out "$KEYS_DIR/aiguard-signer-slhdsa.pub.der" 2>/dev/null
chmod 600 "$KEYS_DIR/aiguard-signer-slhdsa.pem"

P521_HEX="$(xxd -p -c 99999 "$KEYS_DIR/aiguard-signer-p521.pub.der"   | tr -d '\n')"
ED448_HEX="$(xxd -p -c 99999 "$KEYS_DIR/aiguard-signer-ed448.pub.der"  | tr -d '\n')"
MLDSA_HEX="$(xxd -p -c 99999 "$KEYS_DIR/aiguard-signer-mldsa.pub.der"  | tr -d '\n')"
SLHDSA_HEX="$(xxd -p -c 99999 "$KEYS_DIR/aiguard-signer-slhdsa.pub.der" | tr -d '\n')"

# ---- Sanity-check key shapes ------------------------------------------

# P-521 SPKI is 158 bytes (316 hex chars).
# Ed448 SPKI is 69 bytes (138 hex chars).
# ML-DSA-87 SPKI is 2614 bytes (5228 hex chars).
# SLH-DSA-SHA2-256s SPKI is 82 bytes (164 hex chars).
# Tolerate ±4 hex chars for header variants across OpenSSL minor versions.
check_len() {
    local label="$1" hex="$2" lo="$3" hi="$4"
    [ ${#hex} -ge "$lo" ] && [ ${#hex} -le "$hi" ] || {
        echo "$label pubkey unexpected length: ${#hex} (want $lo–$hi)" >&2
        exit 1
    }
}
check_len "P-521"   "$P521_HEX"    312  320
check_len "Ed448"   "$ED448_HEX"   134  142
check_len "ML-DSA"  "$MLDSA_HEX"   5224 5232
check_len "SLH-DSA" "$SLHDSA_HEX"  160  168

# ---- Report ------------------------------------------------------------

cat <<EOF

  ✓ ECDSA P-521         → keys/aiguard-signer-p521.{pem,pub.der}
  ✓ Ed448               → keys/aiguard-signer-ed448.{pem,pub.der}
  ✓ ML-DSA-87           → keys/aiguard-signer-mldsa.{pem,pub.der}
  ✓ SLH-DSA-SHA2-256s   → keys/aiguard-signer-slhdsa.{pem,pub.der}

Next: paste the FOUR values below into
  android/app/src/main/kotlin/dev/tetherand/app/aiguard/runtime/ModelUpdater.kt

────────────────────────────────────────────────────────────────────────
P521_PUBKEY_HEX (${#P521_HEX} hex chars):

$P521_HEX

────────────────────────────────────────────────────────────────────────
ED448_PUBKEY_HEX (${#ED448_HEX} hex chars):

$ED448_HEX

────────────────────────────────────────────────────────────────────────
MLDSA_PUBKEY_HEX (${#MLDSA_HEX} hex chars):

$MLDSA_HEX

────────────────────────────────────────────────────────────────────────
SLHDSA_PUBKEY_HEX (${#SLHDSA_HEX} hex chars):

$SLHDSA_HEX

────────────────────────────────────────────────────────────────────────

After pasting and re-building the APK, sign manifests with:

  bash scripts/sign-manifest.sh \\
       keys/aiguard-signer-p521.pem   \\
       keys/aiguard-signer-ed448.pem  \\
       keys/aiguard-signer-mldsa.pem  \\
       keys/aiguard-signer-slhdsa.pem \\
       <your-manifest-body.json> > <output.json>

Keep the four .pem files OFFLINE — air-gapped, ideally split across
custodians. Anyone with all four can sign your release-channel; they
ARE the release-channel identity. The quadruple verifier defends
against compromise of any THREE keys (or any one family-wide
cryptographic break — classical, lattice, or hash-based).

EOF
