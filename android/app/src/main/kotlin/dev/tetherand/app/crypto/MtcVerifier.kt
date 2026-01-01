package dev.tetherand.app.crypto

import android.util.Log
import org.json.JSONObject
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.security.KeyFactory

/**
 * Sigsum-style Merkle Tree Certificate (MTC) inclusion-proof verifier.
 *
 * Verifies that the manifest body whose `body_sha256` is given was
 * present in a Sigsum-class transparency log at the time the cited
 * tree-head was signed. The verification chain:
 *
 *   leaf  = SHA-256(body_bytes)
 *   root* = compute_merkle_root(leaf, inclusion_proof, leaf_index, tree_size)
 *   tree_head = { tree_size, root, key_hash, … }
 *   sig   = Ed25519(log_pubkey, tree_head_serialization)
 *
 * Inputs (carried in the `mtc_proof` field of the manifest wrapper):
 *
 *   {
 *     "log_id":          "<hex of SHA-256(log_pubkey)>",
 *     "tree_size":        <u64>,
 *     "root_hash":       "<hex 32 bytes>",
 *     "leaf_index":       <u64>,
 *     "inclusion_path":  ["<hex 32 bytes>", …],   // bottom-up sibling hashes
 *     "tree_head_sig":   "<hex 64 bytes — Ed25519 over the tree-head ASCII form>"
 *   }
 *
 * Pinned log pubkeys: a small set of Sigsum logs the project trusts.
 * Initially pinned to the upstream Sigsum demo log; the project's
 * own log gets added as soon as one is provisioned. A proof from any
 * pinned log is accepted; proofs from unknown logs are rejected even
 * if otherwise valid.
 *
 * **Default-allow-on-empty.** A manifest with no `mtc_proof` field
 * (or an empty one) is accepted today — the field is forward-compat
 * scaffolding. Once the project's own Sigsum log is in production,
 * the calling code (`ModelUpdater`) will flip a flag to REQUIRE a
 * present-and-valid proof. Doing the flip without the verifier in
 * place would have blocked manifest updates before the log even
 * existed; doing the verifier without the flip is the safe order.
 */
object MtcVerifier {

    /**
     * Pinned Sigsum log pubkeys. Map key = SHA-256(pubkey) hex; value
     * = the X.509-SPKI-encoded Ed25519 pubkey (DER hex). Two slots
     * shipped today:
     *
     *   1. Upstream Sigsum demo log (https://test.sigsum.org).
     *      Used during v0.1 round-trip testing only — manifests
     *      signed against this log are accepted but DO NOT prove
     *      Tetherand-project commitment, since anyone can submit
     *      to the demo log.
     *
     *   2. A reserved slot for the Tetherand-project Sigsum log.
     *      When provisioned, the slot below gets the real pubkey
     *      and the demo-log slot is removed.
     */
    private val pinnedLogs: Map<String, ByteArray> = mapOf(
        // Sigsum demo log Ed25519 pubkey (SPKI DER hex).
        // Source: https://test.sigsum.org/key-and-policy.html
        // 32-byte raw key prefixed with the Ed25519 SPKI header:
        //   30 2A 30 05 06 03 2B 65 70 03 21 00 <32 bytes>
        "DEMO" to hexToBytes(
            "302a300506032b6570032100" +
            // Demo log key (subject to upstream rotation; re-capture before relying)
            "9d28bbe1d2af9b4c5b8edaa0f10ddb3c8e75c2adc54d39c1cc41eef85f6f37ac"
        ),
        // Reserved for the Tetherand-project log. When set, REPLACE
        // the demo-log entry above — keeping both would allow demo-log
        // submitters to ship manifests as if they were ours.
        // "TETHERAND" to hexToBytes("…"),
    )

    /**
     * Verify the `mtc_proof` JSON against the given body SHA-256.
     *
     * @return `true` if the proof is well-formed AND the inclusion
     *   walk reconstructs the root claimed in the proof AND that root
     *   was signed by a pinned log. `false` on any failure. Empty /
     *   missing proof → `true` (forward-compat scaffolding — see file
     *   docstring).
     */
    fun verify(mtcProofJson: String, bodySha256Hex: String): Boolean {
        if (mtcProofJson.isEmpty()) {
            // Default-allow path. Caller (ModelUpdater) decides
            // whether to log this as a v0.1 fallback acceptance.
            return true
        }
        return try {
            val proof = JSONObject(mtcProofJson)

            val logId = proof.getString("log_id")
            val pubkey = resolvePinnedLog(logId)
                ?: run { Log.w(TAG, "mtc: log_id $logId not in pinned set; reject"); return false }

            val treeSize = proof.getLong("tree_size")
            val rootHash = hexToBytes(proof.getString("root_hash"))
            val leafIndex = proof.getLong("leaf_index")
            val pathArr = proof.getJSONArray("inclusion_path")
            val path = (0 until pathArr.length()).map { hexToBytes(pathArr.getString(it)) }
            val treeHeadSig = hexToBytes(proof.getString("tree_head_sig"))

            // Step 1: compute the leaf hash (Sigsum leaf format =
            // SHA-256(0x00 || body_sha256_bytes) — domain-separating
            // leaf vs internal-node hashes).
            val bodySha = hexToBytes(bodySha256Hex)
            val leafHash = leafHash(bodySha)

            // Step 2: walk the inclusion proof upward.
            val computedRoot = walkInclusionProof(leafHash, path, leafIndex, treeSize)
            if (!computedRoot.contentEquals(rootHash)) {
                Log.w(TAG, "mtc: computed root does not match claimed root")
                return false
            }

            // Step 3: serialize the tree-head per Sigsum's ASCII format
            // and verify the Ed25519 signature over it.
            val treeHeadBytes = serializeTreeHead(treeSize, rootHash)
            if (!verifyEd25519(pubkey, treeHeadBytes, treeHeadSig)) {
                Log.w(TAG, "mtc: tree-head signature does not verify under pinned log pubkey")
                return false
            }

            true
        } catch (t: Throwable) {
            Log.w(TAG, "mtc verify failed: ${t.javaClass.simpleName} — ${t.message}")
            false
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private const val TAG = "MtcVerifier"

    private fun resolvePinnedLog(logId: String): ByteArray? = pinnedLogs[logId]

    /**
     * Sigsum leaf hash: `SHA-256(0x00 || message)`. The 0x00 prefix
     * domain-separates leaf hashes from internal-node hashes (which
     * use 0x01) per RFC 6962 (Certificate Transparency) — Sigsum
     * adopts the same convention.
     */
    private fun leafHash(message: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(0x00)
        md.update(message)
        return md.digest()
    }

    /**
     * Internal-node hash: `SHA-256(0x01 || left || right)`.
     */
    private fun internalHash(left: ByteArray, right: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(0x01)
        md.update(left)
        md.update(right)
        return md.digest()
    }

    /**
     * Walk the inclusion proof bottom-up. At each level, the bit of
     * `leafIndex` corresponding to the current level decides whether
     * the sibling sits to the left or the right of our running hash.
     * Stops once we've consumed the whole `path` AND climbed enough
     * levels to cover `treeSize`.
     *
     * Implements the RFC 6962 § 2.1.1 algorithm (Sigsum inherits it).
     */
    private fun walkInclusionProof(
        leafHash: ByteArray,
        path: List<ByteArray>,
        leafIndex: Long,
        treeSize: Long,
    ): ByteArray {
        if (leafIndex >= treeSize) {
            throw IllegalArgumentException("leaf_index >= tree_size")
        }
        var running = leafHash
        var idx = leafIndex
        var lastIndex = treeSize - 1
        var pathPos = 0
        while (lastIndex > 0) {
            if (idx and 1L == 1L || idx == lastIndex) {
                // Right child OR we're the rightmost imperfect node:
                // the sibling sits to our LEFT.
                if (idx and 1L == 1L) {
                    if (pathPos >= path.size) {
                        throw IllegalStateException("inclusion path truncated (expected more)")
                    }
                    running = internalHash(path[pathPos], running)
                    pathPos++
                } else {
                    // We're rightmost but on a left position — no
                    // sibling at this level; pass through.
                }
            } else {
                // Left child: sibling sits to our RIGHT.
                if (pathPos >= path.size) {
                    throw IllegalStateException("inclusion path truncated (expected more)")
                }
                running = internalHash(running, path[pathPos])
                pathPos++
            }
            idx = idx shr 1
            lastIndex = lastIndex shr 1
        }
        if (pathPos != path.size) {
            throw IllegalStateException("inclusion path too long (extra entries: ${path.size - pathPos})")
        }
        return running
    }

    /**
     * Serialize a Sigsum tree-head into the ASCII form used as the
     * Ed25519 sign-input. Per the Sigsum spec (sigsum.org/docs/spec/),
     * the signed tree-head ASCII form is:
     *
     *     "size=<decimal>\nroot_hash=<lowercase hex>\n"
     *
     * The version-1 spec uses a fixed namespace prefix:
     *
     *     "sigsum.org/v1/tree:" || ASCII-form
     *
     * Both the prefix and the trailing newlines are part of the
     * signed bytes.
     */
    private fun serializeTreeHead(size: Long, rootHash: ByteArray): ByteArray {
        val rootHex = rootHash.joinToString("") { "%02x".format(it) }
        val ascii = "sigsum.org/v1/tree:size=$size\nroot_hash=$rootHex\n"
        return ascii.toByteArray(Charsets.UTF_8)
    }

    /**
     * Verify an Ed25519 signature using the standard JCA. Returns
     * `true` if the signature verifies, `false` on any failure
     * (including unsupported algorithm or malformed pubkey).
     */
    private fun verifyEd25519(spkiDer: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        return try {
            val kf = KeyFactory.getInstance("Ed25519")
            val pubkey = kf.generatePublic(X509EncodedKeySpec(spkiDer))
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(pubkey)
            verifier.update(message)
            verifier.verify(signature)
        } catch (_: Throwable) {
            // Fall back to BouncyCastle's Ed25519 if the platform JCA
            // doesn't ship it (very old Android).
            try {
                val kf = KeyFactory.getInstance("Ed25519", "BC")
                val pubkey = kf.generatePublic(X509EncodedKeySpec(spkiDer))
                val verifier = Signature.getInstance("Ed25519", "BC")
                verifier.initVerify(pubkey)
                verifier.update(message)
                verifier.verify(signature)
            } catch (_: Throwable) {
                false
            }
        }
    }

    private fun hexToBytes(s: String): ByteArray {
        val clean = if (s.length % 2 == 1) "0$s" else s
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(clean[i * 2], 16) shl 4) or
                      Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
        return out
    }
}
