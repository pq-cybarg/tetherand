#!/usr/bin/env bash
# Emit SHA-256 + SHA3-256 hashes for every shipped artifact in bin/.
#
# Output: one `.sha256` and one `.sha3-256` sidecar per artifact, plus
# a single `bin/SHASUMS.txt` index file containing every hash for the
# audit / out-of-band-verification workflow.
#
# Why both hashes:
#   - SHA-256: ubiquitous, every verifier on every OS has it.
#   - SHA3-256: distinct construction (Keccak sponge vs Merkle-Damgård),
#     so a collision attack against one doesn't trivially affect the
#     other. Publishing both means an attacker needs to find a multi-
#     hash collision, which there's no known method for.
#
# Both readouts use openssl 3.x (sha3-256 needs >= 3.2). Fall back to a
# python3 hashlib one-liner if openssl is older.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/bin"
INDEX="$BIN/SHASUMS.txt"

# Use openssl if it ships sha3-256, else fall back to python.
if openssl list -digest-commands 2>/dev/null | grep -q sha3-256; then
    sha3() { openssl dgst -sha3-256 "$1" | awk '{print $NF}'; }
else
    sha3() { python3 -c "import hashlib, sys; print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"; }
fi
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

: > "$INDEX"
echo "# Tetherand build artefact hashes ($(date -u +%Y-%m-%dT%H:%M:%SZ))"  >> "$INDEX"
echo "# Two independent hash functions per file. Compare both before"      >> "$INDEX"
echo "# trusting any artefact pulled from a release page or mirror."       >> "$INDEX"
echo                                                                       >> "$INDEX"

count=0
for f in "$BIN"/* ; do
    [ -f "$f" ] || continue
    case "$f" in
        *.sha256|*.sha3-256|"$INDEX"|*.gitkeep) continue ;;
    esac
    name="$(basename "$f")"
    s256=$(sha256 "$f")
    s3=$(sha3 "$f")
    printf '%s  %s\n' "$s256" "$name" > "$f.sha256"
    printf '%s  %s\n' "$s3"   "$name" > "$f.sha3-256"
    printf 'SHA256     %s  %s\n' "$s256" "$name" >> "$INDEX"
    printf 'SHA3-256   %s  %s\n' "$s3"   "$name" >> "$INDEX"
    count=$((count + 1))
done

echo "  ✓ hashed $count artefact(s) into $INDEX + per-file sidecars"
