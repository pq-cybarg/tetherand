#!/usr/bin/env bash
# Emit every combination of native-lib bundles as a zip with independent
# SHA-256 + SHA3-256 hashes. Each bundle is a logical group of one or
# more .so files that ship as a unit:
#
#   wg    — libtetherand_wg.so                (M3 WireGuard hop)
#   tor   — libtetherand_tor.so               (M6 Tor / Arti hop)
#   nym   — libtetherand_nym.so               (M5 NymVPN hop)
#   pt    — libtetherand_pt.so                (M6.x obfs4 / meek /
#                                              webtunnel PT bridge)
#   pts   — libconjure_client.so [+ snowflake] (M6.x Go-upstream PTs)
#   sdr   — librtlsdr.so + libhackrf.so +
#           libusb-1.0.so                       (M7b SDR stack)
#
# 6 groups → 2^6 = 64 combinations (including the empty one). Each
# combination becomes one zip under dist/bundles/, named with the
# sorted group codes. The empty combination is a bare manifest noting
# the bundle is intentionally empty (verification-of-absence artefact).

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
JNI="$REPO/android/app/src/main/jniLibs/arm64-v8a"
OUT="$REPO/dist/bundles"
INDEX="$OUT/COMBOSUMS.txt"
mkdir -p "$OUT"
rm -f "$OUT"/*.zip "$OUT"/*.sha256 "$OUT"/*.sha3-256 "$INDEX"

# Group → space-separated .so list. A group is included in a combo
# only if EVERY file in its list exists.
declare -A GROUP
GROUP[wg]="libtetherand_wg.so"
GROUP[tor]="libtetherand_tor.so"
GROUP[nym]="libtetherand_nym.so"
GROUP[pt]="libtetherand_pt.so"
GROUP[pts]="libconjure_client.so libsnowflake_client.so"
GROUP[sdr]="librtlsdr.so libhackrf.so libusb-1.0.so"

# Determine which groups have ALL their files present.
present_groups=()
for g in wg tor nym pt pts sdr; do
    ok=1
    for f in ${GROUP[$g]}; do
        [ -f "$JNI/$f" ] || ok=0
    done
    # Special-case `pts`: snowflake skipped due to upstream Go 1.26
    # incompat — accept the group with just conjure.
    if [ "$g" = "pts" ] && [ -f "$JNI/libconjure_client.so" ]; then ok=1; fi
    [ $ok -eq 1 ] && present_groups+=("$g")
done
N=${#present_groups[@]}
echo "Present groups ($N): ${present_groups[*]}"

# Hashes.
if openssl list -digest-commands 2>/dev/null | grep -q sha3-256; then
    sha3() { openssl dgst -sha3-256 "$1" | awk '{print $NF}'; }
else
    sha3() { python3 -c "import hashlib, sys; print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"; }
fi
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

{
    echo "# Tetherand native-bundle combinations ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo "# Each row: SHA-256 + SHA3-256 over the named zip."
    echo "# Two independent hash functions per file."
    echo
} > "$INDEX"

count=0
# 2^N combinations including the empty one.
for ((mask=0; mask < (1 << N); mask++)); do
    selected=()
    for ((i=0; i < N; i++)); do
        if (( (mask >> i) & 1 )); then
            selected+=("${present_groups[i]}")
        fi
    done

    if [ ${#selected[@]} -eq 0 ]; then
        name="tetherand-libs-none"
        manifest_label="(empty — verification-of-absence artefact)"
    else
        # Sort group codes for deterministic naming.
        sorted=$(printf '%s\n' "${selected[@]}" | sort | paste -sd+ -)
        name="tetherand-libs-$sorted"
        manifest_label="${selected[*]}"
    fi

    stage="$(mktemp -d)"
    mkdir -p "$stage/lib/arm64-v8a"
    {
        echo "# Tetherand native-bundle manifest"
        echo "groups:    $manifest_label"
        echo "android:   lib/arm64-v8a/<file>"
        echo "host:      copy files into android/app/src/main/jniLibs/arm64-v8a/"
        echo "           OR ship as a feature-module / OBB."
        echo
        echo "contents:"
    } > "$stage/MANIFEST.txt"
    for g in "${selected[@]}"; do
        for f in ${GROUP[$g]}; do
            if [ -f "$JNI/$f" ]; then
                cp "$JNI/$f" "$stage/lib/arm64-v8a/$f"
                printf '  %-32s  sha256=%s\n' "$f" "$(sha256 "$JNI/$f")" >> "$stage/MANIFEST.txt"
            fi
        done
    done

    zip_path="$OUT/$name.zip"
    (cd "$stage" && zip -qrX "$zip_path" . )
    rm -rf "$stage"

    s256=$(sha256 "$zip_path")
    s3=$(sha3 "$zip_path")
    printf '%s  %s\n' "$s256" "$name.zip" > "$zip_path.sha256"
    printf '%s  %s\n' "$s3"   "$name.zip" > "$zip_path.sha3-256"
    {
        printf 'SHA256     %s  %s\n' "$s256" "$name.zip"
        printf 'SHA3-256   %s  %s\n' "$s3"   "$name.zip"
    } >> "$INDEX"
    count=$((count + 1))
done

echo "  ✓ wrote $count bundle zip(s) into $OUT"
echo "  ✓ master index: $INDEX"
ls -lh "$OUT" | head -20
