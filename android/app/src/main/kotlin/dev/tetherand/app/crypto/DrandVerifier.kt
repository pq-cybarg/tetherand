package dev.tetherand.app.crypto

import android.util.Log
import java.security.MessageDigest
import supranational.blst.BLST_ERROR
import supranational.blst.P1_Affine
import supranational.blst.P2_Affine
import supranational.blst.Pairing

/**
 * BLS12-381 verification for drand-quicknet round signatures.
 *
 * **Why this exists.** Public-randomness beacons absorbed into the
 * `SeekerRng` SHAKE-256 mixer have to be at least TLS-pinned (so a
 * compromised CA can't impersonate `api.drand.sh`) AND Tor-egressed
 * (so the operator doesn't learn our IP). Cryptographically verifying
 * the BLS signature on each round is the THIRD layer: it lets us
 * absorb beacon bytes only if the round was actually signed by the
 * League-of-Entropy threshold pubkey, defending against a compromise
 * of any single drand operator AND against a defective load-balancer
 * cert at api.drand.sh that hands us a different operator's response.
 *
 * **drand quicknet specifics** (https://drand.love/docs/cryptography/):
 *
 *   - Curve: BLS12-381
 *   - SchemeID: `bls-unchained-g1-rfc9380`
 *     → Signature is a G1 element (48 bytes compressed).
 *     → Public key is a G2 element (96 bytes compressed).
 *   - Mode: **unchained** — the message signed for round R is
 *     `SHA-256(R_big_endian_8_bytes)`. No previous_signature in the
 *     input (unlike the legacy default chain).
 *   - DST (domain separation tag for hash-to-curve):
 *     `"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"`
 *   - Verification: `e(G2_neg_generator, sig_g1) * e(pubkey_g2, H(msg)) == 1`
 *     (or equivalently `e(g2, sig) == e(pubkey, H(msg))`).
 *
 * **Implementation strategy.** Uses Supranational's
 * [blst](https://github.com/supranational/blst) — the same audited
 * BLS12-381 library that drand-go's reference client, every Eth2
 * consensus client, and Filecoin all use. Vendored locally as native
 * `libblst.so` (cross-compiled for `arm64-v8a` + `x86_64` under
 * `jniLibs/`) + SWIG-generated `supranational.blst.*` Java bindings
 * under `src/main/java/`. Pulls in `RFC 9380` hash-to-curve, pairing
 * check, and subgroup membership all in one audited primitive.
 *
 * Replaces an earlier Milagro AMCL 0.4 dep (unmaintained, unaudited,
 * legacy try-and-increment hash-to-curve incompatible with drand's
 * RFC 9380 SSWU).
 */
object DrandVerifier {

    /**
     * Quicknet chain pubkey (G2 compressed, 96 bytes = 192 hex chars).
     * Stable and publicly published at
     * `https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info`.
     * Pinned in-code so a compromised drand load-balancer cannot
     * substitute a different chain pubkey.
     *
     * Captured 2026-06-01 from the upstream chain-info endpoint:
     * scheme = `bls-unchained-g1-rfc9380` (SIG on G1, PUBKEY on G2),
     * period = 3s, genesis = 1692803367.
     *
     * **Rotation policy.** drand chain pubkeys rotate rarely (League
     * of Entropy hard fork). When a rotation IS announced upstream,
     * capture the new pubkey from the same `/info` endpoint and
     * replace the constant here. [verifyChainInfoUnchanged] can be
     * called from a periodic monitor to detect upstream rotation
     * BEFORE we silently start absorbing rounds from the wrong chain.
     */
    const val QUICKNET_PUBKEY_HEX =
        "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c" +
        "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb" +
        "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"

    /** Quicknet chain hash — the URL slug. */
    const val QUICKNET_CHAIN_HASH =
        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

    /** DST for quicknet's `bls-unchained-g1-rfc9380` scheme. */
    private const val QUICKNET_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

    /**
     * Decoded quicknet pubkey, lazy-deserialized once via blst. Held
     * as a `P2_Affine` (G2 element). blst validates compression format
     * + subgroup membership during deserialization.
     */
    private val pubkeyG2: P2_Affine? by lazy {
        try {
            val bytes = hexToBytes(QUICKNET_PUBKEY_HEX)
            val pk = P2_Affine(bytes)
            if (!pk.in_group()) {
                Log.w(TAG, "pinned drand pubkey not in G2 prime-order subgroup")
                null
            } else pk
        } catch (t: Throwable) {
            Log.w(TAG, "pubkey deserialize failed: ${t.javaClass.simpleName} — ${t.message}")
            null
        }
    }

    /**
     * Verify a drand-quicknet round signature.
     *
     * @param round the round number from the JSON (`round` field).
     * @param signatureHex the JSON `signature` field (G1 compressed,
     *   48 bytes = 96 hex chars).
     * @return `true` iff the signature verifies under the pinned
     *   quicknet chain pubkey; `false` on any failure (signature
     *   malformed, pairing inequality, blst native lib unavailable,
     *   pubkey deserialize failure, etc.).
     */
    fun verify(round: Long, signatureHex: String): Boolean {
        return try {
            val sigBytes = hexToBytes(signatureHex)
            if (sigBytes.size != 48) {
                Log.w(TAG, "drand sig wrong size: ${sigBytes.size} (expected 48)")
                return false
            }

            val pk = pubkeyG2 ?: return false
            val sig = try { P1_Affine(sigBytes) }
                      catch (t: Throwable) {
                          Log.w(TAG, "sig deserialize failed: ${t.javaClass.simpleName}")
                          return false
                      }
            if (!sig.in_group()) {
                Log.w(TAG, "drand sig not in G1 prime-order subgroup")
                return false
            }

            // Message = SHA-256(round_be_8_bytes) per quicknet unchained mode.
            val msg = sha256(roundToBytes(round))

            // Pairing check via blst's Pairing context. The `true`
            // arg toggles hash-to-curve — blst then internally
            // computes H(msg, DST) = hash_to_curve_g1(msg, DST) and
            // does the pairing equality:
            //     e(G2_neg_generator, sig) * e(pk, H(msg)) == 1
            // which is equivalent to:
            //     e(G2_generator, sig) == e(pk, H(msg))
            val ctx = Pairing(true, QUICKNET_DST)
            // aggregate overload: (P2_Affine pk_in_G2, P1_Affine sig_in_G1, msg, aug)
            // — matches drand quicknet's `bls-unchained-g1-rfc9380` scheme.
            val agg = ctx.aggregate(pk, sig, msg, ByteArray(0))
            if (agg != BLST_ERROR.BLST_SUCCESS) {
                Log.w(TAG, "drand pairing aggregate failed: $agg")
                return false
            }
            ctx.commit()
            ctx.finalverify()
        } catch (t: Throwable) {
            Log.w(TAG, "drand verify threw: ${t.javaClass.simpleName} — ${t.message}")
            false
        }
    }

    /**
     * Sanity-check the pubkey returned by drand's `/info` endpoint
     * against our pinned [QUICKNET_PUBKEY_HEX]. Returns true when
     * they match; false on any mismatch or fetch error.
     *
     * A `false` return is informational ("drand quicknet chain pubkey
     * changed; the pinned constant in DrandVerifier.kt needs a
     * refresh"), NOT a security failure — the pinned constant is the
     * strict trust anchor regardless. A mismatch means we'll continue
     * rejecting rounds + the user gets graceful degradation under the
     * random-oracle defense.
     */
    fun verifyChainInfoUnchanged(infoJson: String): Boolean {
        return try {
            val json = org.json.JSONObject(infoJson)
            val networkPub = json.optString("public_key", "")
            networkPub.equals(QUICKNET_PUBKEY_HEX, ignoreCase = true)
        } catch (_: Throwable) {
            false
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private const val TAG = "DrandVerifier"

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    /** drand round number → 8-byte big-endian. */
    private fun roundToBytes(round: Long): ByteArray {
        val b = ByteArray(8)
        for (i in 0..7) {
            b[7 - i] = ((round ushr (i * 8)) and 0xFF).toByte()
        }
        return b
    }

    private fun hexToBytes(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(s[i * 2], 16) shl 4) or
                      Character.digit(s[i * 2 + 1], 16)).toByte()
        }
        return out
    }
}
