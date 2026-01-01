#!/usr/bin/env bash
# Sign an AI Guard model-bundle manifest body with the hybrid
# ECDSA-P256 + ML-DSA-87 signing keys. Output is the wrapper JSON
# the in-app ModelUpdater consumes.
#
# Usage:
#   bash scripts/sign-manifest.sh \\
#     <ecdsa.pem> <mldsa.pem> <manifest-body.json>
#
# Example:
#   bash scripts/sign-manifest.sh \\
#     keys/aiguard-signer-ecdsa.pem \\
#     keys/aiguard-signer-mldsa.pem \\
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
# OpenSSL 3.5+ is required for native ML-DSA-87 support.

set -euo pipefail

if [ $# -ne 3 ]; then
    echo "Usage: $0 <ecdsa.pem> <mldsa.pem> <manifest-body.json>" >&2
    exit 1
fi

ECDSA_KEY="$1"
MLDSA_KEY="$2"
BODY="$3"

[ -f "$ECDSA_KEY" ] || { echo "ECDSA key not found: $ECDSA_KEY" >&2; exit 1; }
[ -f "$MLDSA_KEY" ] || { echo "ML-DSA key not found: $MLDSA_KEY" >&2; exit 1; }
[ -f "$BODY" ]      || { echo "manifest body not found: $BODY"   >&2; exit 1; }

# Refuse to run with an older OpenSSL that lacks ML-DSA.
if ! openssl pkey -in "$MLDSA_KEY" -text -noout 2>/dev/null | grep -q "ML-DSA"; then
    echo "openssl does not appear to understand ML-DSA-87 (needs 3.5+)" >&2
    exit 1
fi

# 1. ECDSA-P256 / SHA-256 sig over the body's exact bytes (DER-encoded).
SIG_ECDSA_B64="$(openssl dgst -sha256 -sign "$ECDSA_KEY" "$BODY" | base64 | tr -d '\n')"

# 2. ML-DSA-87 sig over the same body bytes. ML-DSA hashes internally
#    per FIPS 204, so we pass the body straight to `openssl pkeyutl
#    -sign` without a digest wrapper.
SIG_MLDSA_B64="$(openssl pkeyutl -sign -inkey "$MLDSA_KEY" -rawin -in "$BODY" | base64 | tr -d '\n')"

# 3. Base64 the body.
BODY_B64="$(base64 -i "$BODY" | tr -d '\n')"

# 4. Emit the wrapper JSON. sigsum_proof is left empty for v1; the
#    in-app verifier accepts a present-but-empty field and logs it.
cat <<EOF
{
  "body": "$BODY_B64",
  "sig_ecdsa_b64": "$SIG_ECDSA_B64",
  "sig_mldsa_b64": "$SIG_MLDSA_B64",
  "sigsum_proof": ""
}
EOF
