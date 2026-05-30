package dev.tetherand.app.aiguard.runtime

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Privacy-chain-only delta-update path for the AI Guard model bundle.
 *
 * The 4-model bundle (`phi-tetherand-3b-q4` + `voiceguard-v1` +
 * `textguard-v1` + `qrguard-v1`, ~2.4 GB compressed) does not ship in
 * the APK — it would bloat the APK past Play's size limits and would
 * be obsolete the moment the model files re-train. Instead the
 * bundle ships as a separate signed download fetched through whatever
 * privacy chain the user has active.
 *
 * The update flow:
 *
 *   1. Fetch `manifest.json` from MANIFEST_URL (over HTTPS).
 *   2. Verify the manifest's ECDSA P-256 signature against the
 *      pubkey pinned at compile time. Manifest is small (few KB), so
 *      the signature covers the whole file.
 *   3. For each model entry in the manifest, fetch the model file,
 *      verify its SHA-256 against the value in the manifest, write to
 *      `filesDir/aiguard/<id>.tflite`.
 *   4. Re-scan AiGuardRuntime so it picks up the new files alongside
 *      whatever was bundled in `assets/aiguard/`.
 *
 * Hard properties:
 *   - The HTTP fetches use the system-default HttpURLConnection, which
 *     respects the active VpnService. If the user has a privacy chain
 *     up, every byte goes through it. There is no out-of-band path.
 *   - The signature gate is non-negotiable: a manifest that fails
 *     verification is discarded immediately, no fallback. The
 *     attacker has to forge an ECDSA P-256 signature against a key
 *     they don't have.
 *   - The hashed-bundle check defends against a partial corruption
 *     during the (potentially long) download — a Tor circuit drop
 *     mid-file shouldn't leave a half-flushed model on disk.
 */
class ModelUpdater(private val ctx: Context) {

    companion object {
        private const val TAG = "AiGuardModelUpdater"
        /** Default manifest endpoint. Override via env / build config
         *  for staging vs production. */
        const val MANIFEST_URL = "https://aiguard.tetherand.dev/v1/manifest.json"

        /** ECDSA P-256 public key in X.509 DER format, hex-encoded.
         *  Pinned at compile time so an attacker who compromises the
         *  manifest origin still cannot ship malicious models. The
         *  PLACEHOLDER constant below must be replaced with a real
         *  pubkey at release-signing time; until then this lives as
         *  an obvious sentinel that aborts every verify (a real key
         *  is 91 hex characters in compressed DER form). */
        const val SIGNING_PUBKEY_HEX =
            "PLACEHOLDER_REPLACE_AT_RELEASE_TIME_91_HEX_CHARS_FOR_X509_ECDSA_P256_PUBKEY"
    }

    data class State(
        val running: Boolean = false,
        val progress: String = "",
        val lastResult: String? = null,
    )

    sealed class Result {
        object Ok : Result()
        data class Failed(val reason: String) : Result()
    }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    private val outDir: File = File(ctx.filesDir, "aiguard").also { it.mkdirs() }

    /** Run a single update cycle. Returns Ok on a successful update
     *  with at least one model written, Failed otherwise. The state
     *  flow tracks progress as the run proceeds so the UI can
     *  re-render. */
    suspend fun checkAndUpdate(manifestUrl: String = MANIFEST_URL): Result = withContext(Dispatchers.IO) {
        if (_state.value.running) return@withContext Result.Failed("already running")
        _state.value = State(running = true, progress = "fetching manifest")

        val manifest = try { fetchAndVerifyManifest(manifestUrl) }
                       catch (t: Throwable) { return@withContext done(Result.Failed("manifest: ${t.message}")) }

        val entries = try {
            val arr = manifest.optJSONArray("models") ?: return@withContext done(Result.Failed("no models[] in manifest"))
            (0 until arr.length()).map { arr.getJSONObject(it) }
        } catch (t: Throwable) {
            return@withContext done(Result.Failed("manifest parse: ${t.message}"))
        }

        var written = 0
        for (entry in entries) {
            val id = entry.optString("id")
            val url = entry.optString("url")
            val expectedHex = entry.optString("sha256")
            if (id.isEmpty() || url.isEmpty() || expectedHex.isEmpty()) continue
            _state.value = _state.value.copy(progress = "downloading $id")
            try {
                val bytes = httpGet(url)
                val actualHex = sha256Hex(bytes)
                if (!actualHex.equals(expectedHex, ignoreCase = true)) {
                    Log.w(TAG, "$id sha256 mismatch: expected=$expectedHex actual=$actualHex")
                    continue
                }
                val f = File(outDir, "$id.tflite")
                f.writeBytes(bytes)
                written++
                _state.value = _state.value.copy(progress = "$id ok (${bytes.size} bytes)")
            } catch (t: Throwable) {
                Log.w(TAG, "$id fetch: $t")
            }
        }

        AiGuardRuntime.get(ctx).loadAll()
        return@withContext done(if (written > 0) Result.Ok else Result.Failed("no models written"))
    }

    private fun done(r: Result): Result {
        val label = when (r) {
            is Result.Ok -> "ok"
            is Result.Failed -> "failed: ${r.reason}"
        }
        _state.value = State(running = false, progress = "", lastResult = label)
        return r
    }

    /** Fetch manifest, verify signature, return the parsed JSON body. */
    private fun fetchAndVerifyManifest(url: String): JSONObject {
        val body = httpGet(url)
        // Manifest format: {"body": "...base64-encoded JSON...", "sig_b64": "..."}.
        // We sign the body field's exact bytes; the wrapper carries
        // both so a downloader can verify without re-canonicalising.
        val outer = JSONObject(String(body, Charsets.UTF_8))
        val bodyB64 = outer.getString("body")
        val sigB64 = outer.getString("sig_b64")

        val bodyBytes = android.util.Base64.decode(bodyB64, android.util.Base64.NO_WRAP)
        val sigBytes = android.util.Base64.decode(sigB64, android.util.Base64.NO_WRAP)

        verifyEcdsaP256(bodyBytes, sigBytes)
        // Body itself is JSON containing the model list.
        return JSONObject(String(bodyBytes, Charsets.UTF_8))
    }

    private fun httpGet(url: String): ByteArray {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 120_000
            setRequestProperty("User-Agent", "Tetherand-AI-Guard/1")
        }
        try {
            val code = conn.responseCode
            if (code != 200) throw IllegalStateException("HTTP $code")
            return conn.inputStream.use { it.readBytes() }
        } finally {
            try { conn.disconnect() } catch (_: Throwable) {}
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    /** Verify an ECDSA P-256 signature using the pinned pubkey.
     *  Throws on either bad signature or unparseable pubkey. */
    private fun verifyEcdsaP256(body: ByteArray, sig: ByteArray) {
        if (SIGNING_PUBKEY_HEX.startsWith("PLACEHOLDER")) {
            throw IllegalStateException(
                "signing pubkey is the compile-time placeholder; release-time keygen required"
            )
        }
        val pubkeyDer = SIGNING_PUBKEY_HEX
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
        val kf = KeyFactory.getInstance("EC")
        val pub = kf.generatePublic(X509EncodedKeySpec(pubkeyDer))
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(pub)
        v.update(body)
        if (!v.verify(sig)) {
            throw IllegalStateException("manifest signature does not verify against pinned pubkey")
        }
    }

    /** Wipe downloaded models (e.g. for a clean reinstall). */
    fun clear() {
        outDir.listFiles()?.forEach { it.delete() }
        AiGuardRuntime.get(ctx).loadAll()
    }
}
