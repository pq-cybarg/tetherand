package dev.tetherand.app.crypto

import android.util.Log
import java.security.MessageDigest

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
 *   - Pubkey: G1 element (48 bytes compressed)
 *   - Signature: G2 element (96 bytes compressed)
 *   - Mode: **unchained** — the message signed for round R is
 *     `SHA-256(R_big_endian_8_bytes)`. No previous_signature in the
 *     input (unlike the legacy default chain).
 *   - DST (domain separation tag for hash-to-curve):
 *     `"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"`
 *   - Verification: `pairing(G1_neg_generator, sig) * pairing(pubkey, H(msg)) == 1`
 *
 * **Implementation strategy.** This class uses the Apache Milagro AMCL
 * pure-Java BLS12-381 implementation (`org.apache.milagro.amcl.BLS381.*`).
 * Pure Java means no NDK / JNI native binding, works on every Android
 * arch, ~500 KB binary cost. Verification is done via the high-level
 * `BLS.core_verify(PK, M, SIG)` entrypoint which performs the
 * hash-to-curve + pairing equality internally.
 *
 * **Reflection-based dispatch.** We reach the Milagro classes via
 * `Class.forName` so the build doesn't hard-fail if the dependency
 * isn't resolved (e.g., in environments where the Maven coordinates
 * have changed or the user has stripped the lib to save binary size).
 * When the lib is absent, `verify()` returns `false` and `PublicBeacons`
 * treats the round as unverified — falling back to the random-oracle
 * absorption argument (the SHAKE-256 mixer still defeats bias even
 * from unverified beacon bytes, but verification rules them in as a
 * stronger source).
 */
object DrandVerifier {

    /**
     * Quicknet chain pubkey (G1 compressed, 48 bytes = 96 hex chars).
     * Stable and publicly published at
     * `https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info`.
     * Pinned in-code so a compromised drand load-balancer cannot
     * substitute a different chain pubkey.
     *
     * Captured 2026-05-31 from the upstream chain-info endpoint:
     * scheme = `bls-unchained-g1-rfc9380`, period = 3s, genesis = 1692803367.
     *
     * **Rotation policy.** drand chain pubkeys rotate rarely (League
     * of Entropy hard fork — the last rotation moved from the legacy
     * `pedersen-bls-chained` chain to quicknet in 2023). When a
     * rotation IS announced upstream, capture the new pubkey from the
     * same `/info` endpoint and replace the constant here, alongside
     * a new [QUICKNET_CHAIN_HASH] if the chain hash also changed.
     *
     * In the meantime, [verifyChainInfoUnchanged] can be called from
     * a periodic monitor to detect upstream rotation BEFORE we
     * silently start absorbing rounds from the wrong chain. Today
     * `PublicBeacons` doesn't call it on the hot path (it would add a
     * second HTTPS round-trip per refresh); future M11.x can move
     * this into the BridgeRotation-style periodic worker.
     */
    const val QUICKNET_PUBKEY_HEX =
        "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c" +
        "8c4b450b6a0a6c3ac6a5776a2d106451"

    /** Quicknet chain hash — the URL slug. */
    const val QUICKNET_CHAIN_HASH =
        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

    /**
     * Sanity-check the pubkey returned by drand's `/info` endpoint
     * against our pinned [QUICKNET_PUBKEY_HEX]. Returns true when
     * they match; false on any mismatch or fetch error.
     *
     * Call sites are expected to surface a `false` return as an
     * informational alert ("drand quicknet chain pubkey changed; the
     * pinned constant in DrandVerifier.kt needs a refresh"), NOT as
     * a security failure — the pinned constant is the strict trust
     * anchor regardless of what the network says. A mismatch means
     * we'll continue to reject rounds (since the network's signatures
     * would now be from a different keypair) and the user gets
     * graceful degradation under the random-oracle defense.
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

    /**
     * Verify a drand-quicknet round signature.
     *
     * @param round the round number from the JSON (`round` field).
     * @param signatureHex the JSON `signature` field (G2 compressed, 96 bytes hex).
     * @return true iff the signature verifies under the pinned quicknet
     *   chain pubkey; false on any failure (signature malformed, pairing
     *   inequality, Milagro library absent, etc.).
     */
    fun verify(round: Long, signatureHex: String): Boolean {
        return try {
            val sigBytes = hexToBytes(signatureHex)
            if (sigBytes.size != 96) {
                Log.w(TAG, "drand sig wrong size: ${sigBytes.size} (expected 96)")
                return false
            }
            val msg = sha256(roundToBytes(round))
            verifyBls12381(QUICKNET_PUBKEY_HEX, msg, sigBytes)
        } catch (t: Throwable) {
            Log.w(TAG, "drand verify threw: ${t.javaClass.simpleName} — ${t.message}")
            false
        }
    }

    // ------------------------------------------------------------------
    // Reflection-based Milagro AMCL dispatch
    // ------------------------------------------------------------------

    /**
     * Use Milagro AMCL's `BLS.core_verify(PK, M, SIG)` (the
     * RFC-9380-compliant entrypoint matching drand's DST). When the
     * library is unavailable, return false rather than throwing —
     * `PublicBeacons` interprets that as "we couldn't verify but the
     * beacon may still be absorbed under the random-oracle defense".
     */
    private fun verifyBls12381(pubkeyHex: String, message: ByteArray, signature: ByteArray): Boolean {
        return try {
            val blsCls = Class.forName("org.apache.milagro.amcl.BLS381.BLS")
            val pubkey = hexToBytes(pubkeyHex)
            // BLS.core_verify(PK, M, SIG) returns 0 on success, anything else on failure.
            val method = blsCls.getMethod(
                "core_verify",
                ByteArray::class.java,
                ByteArray::class.java,
                ByteArray::class.java,
            )
            val rc = method.invoke(null, pubkey, message, signature) as Int
            if (rc == 0) {
                true
            } else {
                Log.w(TAG, "drand BLS verify failed rc=$rc")
                false
            }
        } catch (cnfe: ClassNotFoundException) {
            Log.w(TAG, "Milagro AMCL not on classpath; drand BLS verification skipped (random-oracle absorb still applies)")
            false
        } catch (t: Throwable) {
            Log.w(TAG, "Milagro AMCL dispatch failed: ${t.javaClass.simpleName} — ${t.message}")
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
