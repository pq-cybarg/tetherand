#!/usr/bin/env bash
# Sign an AI Guard model-bundle manifest body with the FOUR signing
# keys (ECDSA P-521 + Ed448 + ML-DSA-87 + SLH-DSA-SHA2-256s). Output
# is the wrapper JSON the in-app ModelUpdater consumes.
#
# Usage:
#   bash scripts/sign-manifest.sh \\
#     <p521.pem> <ed448.pem> <mldsa.pem> <slhdsa.pem> \\
#     <manifest-body.json>
#
# Example:
#   bash scripts/sign-manifest.sh \\
#     keys/aiguard-signer-p521.pem   \\
#     keys/aiguard-signer-ed448.pem  \\
#     keys/aiguard-signer-mldsa.pem  \\
#     keys/aiguard-signer-slhdsa.pem \\
#     examples/manifest-body.json > dist/manifest.json
#
# Body file format:
#   {
#     "models": [
#       {"id": "phi-tetherand-3b-q4", "url": "...", "sha256": "..."},
#       {"id": "voiceguard-v1",       "url": "...", "sha256": "..."},
#       ...
#     ]
#   }
#
# OpenSSL 3.5+ is required for native ML-DSA-87 + SLH-DSA-SHA2-256s
# + Ed448. OpenSSL 3.6 is the tested floor.
#
# The wrapper format consumed by ModelUpdater.kt is:
#   {
#     "body":           "<base64 canonical JSON>",
#     "sig_p521_b64":   "<ECDSA P-521 / SHA-512 DER>",
#     "sig_ed448_b64":  "<Ed448 pure-EdDSA>",
#     "sig_mldsa_b64":  "<ML-DSA-87>",
#     "sig_slhdsa_b64": "<SLH-DSA-SHA2-256s>",
#     "mtc_proof":      "<optional MTC inclusion proof — empty in v1>"
#   }
# ALL FOUR signatures must verify or the manifest is rejected. The
# verifier runs cheap → expensive (P-521 → Ed448 → ML-DSA → SLH-DSA)
# and short-circuits on the first failure.

set -euo pipefail

if [ $# -ne 5 ]; then
    echo "Usage: $0 <p521.pem> <ed448.pem> <mldsa.pem> <slhdsa.pem> <manifest-body.json>" >&2
    exit 1
fi

P521_KEY="$1"
ED448_KEY="$2"
MLDSA_KEY="$3"
SLHDSA_KEY="$4"
BODY="$5"

[ -f "$P521_KEY"   ] || { echo "P-521 key not found: $P521_KEY"     >&2; exit 1; }
[ -f "$ED448_KEY"  ] || { echo "Ed448 key not found: $ED448_KEY"    >&2; exit 1; }
[ -f "$MLDSA_KEY"  ] || { echo "ML-DSA key not found: $MLDSA_KEY"   >&2; exit 1; }
[ -f "$SLHDSA_KEY" ] || { echo "SLH-DSA key not found: $SLHDSA_KEY" >&2; exit 1; }
[ -f "$BODY"       ] || { echo "manifest body not found: $BODY"     >&2; exit 1; }

# Refuse to run with an older OpenSSL that lacks any of the PQ algorithms.
if ! openssl pkey -in "$MLDSA_KEY" -text -noout 2>/dev/null | grep -q "ML-DSA"; then
    echo "openssl does not appear to understand ML-DSA-87 (needs 3.5+)" >&2
    exit 1
fi
if ! openssl pkey -in "$SLHDSA_KEY" -text -noout 2>/dev/null | grep -qiE "SLH-DSA|SPHINCS"; then
    echo "openssl does not appear to understand SLH-DSA (needs 3.5+)" >&2
    exit 1
fi

# 1. ECDSA P-521 / SHA-512 signature (DER-encoded). FIPS 186-5 pairs
#    P-521 with SHA-512; matches what ModelUpdater.kt requests via
#    Signature.getInstance("SHA512withECDSA").
SIG_P521_B64="$(openssl dgst -sha512 -sign "$P521_KEY" "$BODY" | base64 | tr -d '\n')"

# 2. Ed448 pure-EdDSA signature (no separate hash — RFC 8032 mandates
#    Ed448 takes the message bytes directly and hashes internally with
#    SHAKE-256).
SIG_ED448_B64="$(openssl pkeyutl -sign -inkey "$ED448_KEY" -rawin -in "$BODY" | base64 | tr -d '\n')"

# 3. ML-DSA-87 signature. ML-DSA hashes internally per FIPS 204, so
#    we pass the body straight to `openssl pkeyutl -sign` without a
#    digest wrapper. -rawin tells openssl to skip its default
#    pre-hashing step.
SIG_MLDSA_B64="$(openssl pkeyutl -sign -inkey "$MLDSA_KEY" -rawin -in "$BODY" | base64 | tr -d '\n')"

# 4. SLH-DSA-SHA2-256s signature. SLH-DSA is stateless hash-based per
#    FIPS 205; same -rawin convention as ML-DSA. Signing is slow
#    (seconds, not milliseconds) because SLH-DSA trades signing cost
#    for tiny pubkeys + no lattice assumptions.
SIG_SLHDSA_B64="$(openssl pkeyutl -sign -inkey "$SLHDSA_KEY" -rawin -in "$BODY" | base64 | tr -d '\n')"

# 5. Base64 the body.
BODY_B64="$(base64 -i "$BODY" | tr -d '\n')"

# 6. Emit the wrapper JSON. mtc_proof is left empty for v1; the
#    in-app verifier accepts a present-but-empty field and logs it.
#    The M10.x log-walk verifier will populate this when MTC /
#    Sigsum / Trillian transparency-log integration ships.
cat <<EOF
{
  "body": "$BODY_B64",
  "sig_p521_b64": "$SIG_P521_B64",
  "sig_ed448_b64": "$SIG_ED448_B64",
  "sig_mldsa_b64": "$SIG_MLDSA_B64",
  "sig_slhdsa_b64": "$SIG_SLHDSA_B64",
  "mtc_proof": ""
}
EOF
