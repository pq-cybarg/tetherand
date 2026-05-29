#!/usr/bin/env bash
# Create a GitHub release for the named tag and upload every build
# artefact (APK + 64 combo zips + index files + their .sha256 +
# .sha3-256 sidecars).
#
# Usage:  bash scripts/release-upload.sh v0.1
#
# Pre-req: gh auth login (one-time interactive — `gh auth login --hostname github.com`)
#          run from a shell with $HOME/.config/gh writable.

set -euo pipefail

TAG="${1:-v0.1}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TITLE="Tetherand $TAG"

gh auth status >/dev/null 2>&1 || { echo "Run 'gh auth login' first (interactive)."; exit 1; }

# Body sourced from the annotated-tag message so the release page and
# the git tag stay in lockstep.
BODY="$(git tag -l --format='%(contents)' "$TAG")"

# Create the release (idempotent — --clobber overwrites assets if rerun).
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release $TAG already exists — uploading assets with --clobber."
    UPLOAD="gh release upload $TAG --clobber"
else
    echo "Creating release $TAG."
    gh release create "$TAG" \
        --title "$TITLE" \
        --notes "$BODY" \
        --verify-tag
    UPLOAD="gh release upload $TAG"
fi

# Stage the asset list. Primary artefacts get pinned at the top of the
# release page; combination zips follow.
ASSETS=(
    "$REPO/bin/tetherand.apk"
    "$REPO/bin/tetherand.apk.sha256"
    "$REPO/bin/tetherand.apk.sha3-256"
    "$REPO/bin/SHASUMS.txt"
    "$REPO/dist/bundles/COMBOSUMS.txt"
)
# Add every combo zip + its two sidecars.
for z in "$REPO"/dist/bundles/tetherand-libs-*.zip; do
    ASSETS+=("$z" "$z.sha256" "$z.sha3-256")
done

# Upload in batches of 20 to keep gh's HTTP timeouts happy.
batch=()
n=0
for a in "${ASSETS[@]}"; do
    [ -f "$a" ] || { echo "  skip (missing): $a"; continue; }
    batch+=("$a")
    n=$((n + 1))
    if [ ${#batch[@]} -ge 20 ]; then
        echo "  uploading batch of ${#batch[@]} …"
        $UPLOAD "${batch[@]}"
        batch=()
    fi
done
if [ ${#batch[@]} -gt 0 ]; then
    echo "  uploading final batch of ${#batch[@]} …"
    $UPLOAD "${batch[@]}"
fi
echo "  ✓ $n asset(s) uploaded to release $TAG"
gh release view "$TAG" 2>&1 | head -8
