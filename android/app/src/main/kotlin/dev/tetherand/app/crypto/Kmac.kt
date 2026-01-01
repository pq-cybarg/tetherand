package dev.tetherand.app.crypto

import org.bouncycastle.crypto.macs.KMAC
import java.util.Arrays

/**
 * KMAC (KECCAK Message Authentication Code) — NIST SP 800-185.
 *
 * A modern alternative to HMAC built directly on KECCAK. Compared to
 * HMAC-SHA-* it has:
 *
 *   - Cleaner construction (HMAC was designed to safely use insecure
 *     hash functions; KMAC does NOT need the inner+outer key wrapping).
 *   - Lower latency per byte (1 KECCAK absorb vs HMAC's 2 full hashes).
 *   - Native variable-output length (great for KDF use without a
 *     separate HKDF wrapper).
 *   - Domain-separating customization string baked into the spec —
 *     no risk of cross-protocol collision when the same key is used
 *     for multiple purposes.
 *
 * Two parameter sets per SP 800-185:
 *   - KMAC128: 128-bit security level, 168-byte rate
 *   - KMAC256: 256-bit security level, 136-byte rate
 *
 * **When to use this vs. HMAC:**
 *   - **HMAC stays** for (a) wire-protocol-compat constraints — nym-sdk,
 *     TLS, anywhere a peer expects HMAC bytes; and (b) AndroidKeyStore
 *     HW-keystore operations — `KeyProperties.KEY_ALGORITHM_*` ships
 *     `HmacSHA256/384/512` only, no KMAC, so the key would have to leave
 *     the keystore which defeats the StrongBox/TEE protection.
 *   - **KMAC is the right pick** for any new internal MAC site where
 *     we control both ends and the key material doesn't need to live
 *     in the HW keystore — e.g., authenticated app-internal channels,
 *     domain-separated derivation tags, integrity over locally-stored
 *     blobs that we encrypt/decrypt in software.
 *
 * Implementation note: BouncyCastle 1.80 ships `KMAC` directly under
 * `org.bouncycastle.crypto.macs.KMAC`. The class takes (bitStrength,
 * customizationString) and a Mac-style key + update + doFinal lifecycle.
 *
 * No call sites yet — this is a primitive on standby for future
 * internal-MAC needs. Adding it pre-need so the import is one line
 * away when a use case appears.
 */
object Kmac {

    /**
     * Compute KMAC256(key, message, customization) → `outLen` bytes.
     *
     * @param key Variable-length key material. SP 800-185 places no
     *   strict bounds; security floor is the key entropy.
     * @param message Message to authenticate.
     * @param customization Optional domain-separation tag (bound into
     *   the MAC computation). Empty string is allowed but discouraged
     *   for new sites — pick a unique tag per purpose so two different
     *   MAC computations under the same key cannot collide.
     * @param outLen Desired output length in bytes (variable per SP
     *   800-185; KMAC supports arbitrary output). Default 32 bytes
     *   matches HMAC-SHA-256 output size.
     */
    fun kmac256(
        key: ByteArray,
        message: ByteArray,
        customization: String = "",
        outLen: Int = 32,
    ): ByteArray {
        val mac = KMAC(256, customization.toByteArray(Charsets.UTF_8))
        mac.init(org.bouncycastle.crypto.params.KeyParameter(key))
        mac.update(message, 0, message.size)
        val out = ByteArray(outLen)
        // BC's KMAC.doFinal returns the FIXED 32-byte digest size by
        // default but supports XOF via doOutput when initialized for
        // arbitrary length. For the common 32-byte case, doFinal is
        // sufficient and matches HMAC-SHA-256 ergonomics.
        if (outLen == mac.macSize) {
            mac.doFinal(out, 0)
        } else {
            // Variable-output path: BC KMAC implements Xof when the
            // requested output exceeds the default mac size. Use
            // doOutput which writes XOF squeeze bytes.
            mac.doOutput(out, 0, outLen)
        }
        return out
    }

    /**
     * Constant-time tag-verify. Computes KMAC256 over (key, message,
     * customization, len=tag.size) and compares with `tag` using a
     * length-independent equality check.
     *
     * Returns false on any mismatch (including length mismatch).
     */
    fun verify(
        key: ByteArray,
        message: ByteArray,
        customization: String,
        tag: ByteArray,
    ): Boolean {
        val computed = kmac256(key, message, customization, tag.size)
        return try {
            constantTimeEq(computed, tag)
        } finally {
            Arrays.fill(computed, 0)
        }
    }

    private fun constantTimeEq(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
