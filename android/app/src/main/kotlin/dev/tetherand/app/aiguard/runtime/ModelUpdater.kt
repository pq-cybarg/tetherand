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
import java.security.Security
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Privacy-chain-only delta-update path for the AI Guard model bundle.
 *
 * The 4-model bundle (`phi-tetherand-3b-q4` + `voiceguard-v1` +
 * `textguard-v1` + `qrguard-v1`, ~2.4 GB compressed) ships outside
 * the APK as a separate signed download fetched through whatever
 * privacy chain the user has active.
 *
 * # Signature posture — quadruple-signed, highest security available
 *
 * The manifest is signed FOUR times. All four must verify or the
 * manifest is rejected. Each signature pins a different cryptographic
 * assumption so the attacker has to break ALL of them to forge:
 *
 *   1. **ECDSA P-521 / SHA-512** — NIST classical, security Level 5
 *      (256-bit). The "today" load-bearing signature.
 *   2. **Ed448 (pure EdDSA)** — non-NIST Edwards curve, ~Level 4
 *      classical (224-bit). Defends against a hypothetical break /
 *      backdoor in NIST-curve generation.
 *   3. **ML-DSA-87** — NIST PQC FIPS 204, lattice-based, Level 5.
 *      Defends against a quantum signing forge against classical
 *      legs. Standardised composite-sigs pairing per IETF
 *      `draft-ietf-lamps-pq-composite-sigs` v19 (21-Apr-2026)
 *      composite #18 `id-MLDSA87-ECDSA-P521-SHA512`
 *      (OID 1.3.6.1.5.5.7.6.54).
 *   4. **SLH-DSA-SHA2-256s** — NIST PQC FIPS 205, stateless hash-
 *      based, Level 5. Defends against a hypothetical break in
 *      lattice cryptography that doesn't touch hash functions —
 *      the most conservative PQ assumption available.
 *
 * Forging the manifest requires:
 *   - classical cryptanalysis of P-521 (factor ~2^256 work) AND
 *   - classical cryptanalysis of Ed448 (~2^224 work) AND
 *   - a quantum signing forge of ML-DSA-87 (no known algorithm) AND
 *   - a hash-pre-image / collision attack on SHA-256 that defeats
 *     SLH-DSA-256s's 256-bit-equivalent FORS+XMSS construction.
 *
 * Even a complete break of EITHER side of the classical/PQ divide
 * leaves the other still standing. Even a break of lattice cryptography
 * leaves the hash-based PQ leg.
 *
 * # IETF + NIST compliance
 *
 *   - **FIPS 204 ML-DSA** (final, 13-Aug-2024): ML-DSA-87 parameter set.
 *     IETF `draft-ietf-lamps-pq-composite-sigs` v19 composite #18
 *     `id-MLDSA87-ECDSA-P521-SHA512` covers our ML-DSA-87 + P-521 pair.
 *     Our additional Ed448 and SLH-DSA legs exceed the standard.
 *   - **FIPS 205 SLH-DSA** (final, 13-Aug-2024): SLH-DSA-SHA2-256s
 *     parameter set. Stateless — no per-key counter state to lose
 *     in the build pipeline.
 *   - **NOT used**: stateful hash-based signatures (LMS/XMSS, NIST
 *     SP 800-208). State-loss risk in a CI signer outweighs the
 *     marginal security benefit over SLH-DSA stateless.
 *   - **FIPS 203 ML-KEM**: not used here directly. M4 Mullvad PQ
 *     tunnel uses ML-KEM-1024 via the WG PSK overlay (see
 *     `relay/wg/src/kem.rs`).
 *
 * # Transparency hook — Google MTC + Sigsum
 *
 * The wrapper carries an optional `mtc_proof` field — a Merkle Tree
 * Certificate inclusion proof per the Google + Cloudflare spec being
 * standardised in the IETF PLANTS WG (Feb 2026 announcement). MTC
 * replaces per-artefact signatures with compact inclusion proofs
 * against a CA-signed Merkle tree head, shrinking the per-cert PQ
 * footprint from ~14.7 KB to ~736 B.
 *
 * For our use case (signing a manifest a few times per year) MTC is
 * overkill, but the field is reserved so a future move to MTC + a
 * Sigsum / Trillian log doesn't break the wrapper format. v1 logs
 * a present proof and accepts it unconditionally; the log-walk
 * verifier ships in M10.x.
 */
class ModelUpdater(private val ctx: Context) {

    companion object {
        private const val TAG = "AiGuardModelUpdater"

        const val MANIFEST_URL = "https://aiguard.tetherand.dev/v1/manifest.json"

        /** Classical NIST L5 signing pubkey — ECDSA P-521 SPKI hex. */
        const val P521_PUBKEY_HEX = "30819b301006072a8648ce3d020106052b810400230381860004005a5d172c1363881b54f03449fa3af9487a5f2fa6bd50e0113e7803335af69d09feb523a5151e62799a87a635c2bbd527fb13b5db73c093e6ca7a19080d4abffb26010f1b2bfb8b97d674dfddb61cab5f436489d8e4d975f4cc6d3cb0283439911bb637ecbe22e53632668c8b2c2b67e36f4ff66e7b3787f962589b06ff2830251680a8"

        /** Non-NIST classical signing pubkey — Ed448 SPKI hex.
         *  Insurance against a hypothetical NIST-curve weakness. */
        const val ED448_PUBKEY_HEX = "3043300506032b6571033a00839f8ab0c3d4d76b03784e5770bc70b2b8989c8065d9a6eecade3c78c86a091dfe6c316dd756cd333ca179046c8d4ba2e819e631c744731f00"

        /** PQ lattice signing pubkey — ML-DSA-87 (FIPS 204) SPKI hex. */
        const val MLDSA_PUBKEY_HEX = "30820a32300b060960864801650304031303820a2100a698e561e24d176a5adb7a71806671bb630367fa64c9933d26d3bff2fa6fd4147ef0b14098a0ad8bbfe3c7483b6569825de2954aea9bb38a7d500da31cce710715ad0aae53fceb64476920ac7b1245659f72366c58befc8f0c8bd069ab092ba52ea38c8b515ecd35fae11587e7dadd27424bf6aea0ae1840ec40320f8505fa7047d4e14e0c56391866d2a0db2c42fc711684bf934673b71381af0741d50e42c755380abd93a3d9f6ed63605f967dafdeaf36a15db067cd78afe0c50a6715b2bff4d35503f29f98b5ef14afb75547481f68ea58bb4569a81731844537636ade12119d63318ad00e649c4dcecbebec39fb7293d16424350731333137e72e054c03fda9fef083455182ee6eddf5e85a46b6a762632ab23950358f9d2e52e935d084a980ae840236e9aafb55f5b98e6e42e1475202a8a89465efb0a18eff2f17727ed66c8fd6af62fe4088cba3f046d742d18374c768988b884f8b06858e17b09d5df919642ecfe3d53f53f62669e30e14a18e522663a80d40164def6169249097ee8d8897fc122276cd3fac981321339ec978aeaa8055b76ea1687e6c7eb60512697284f3f80acb8d97feb597b6a3710da93647b74c2f95476ada1bf2c56eabc6e2d19ee433af37cc0d95db1b7e67478a247905d3deb89abb4dc3fc21312eef4b39339be5cafff62e3f938b4ad102c5f6a087ac6a5cd1898f0b484cdd6ff2319b174bb885e685cc9ce4b87bb55eb5caf999963634b0d5d4caa3d6b7218d9b735fe6b9307755a3456882198c16706a31f0a49d1e7715211745046256bd321dec332409100d4c3236364f1127581ae84306aa76791afb8ccbfdbbe92dbe8a923324114301509bc3221af99527b7e843925e3f2318209e4582e0b8dc6df2b0d81c621db5662babb9dea85c1800ab833e714a35a1a68e6f25ce5a8d3e764a5196907e69612d7bec31e90836621b4d164fcc49dadb752ebf6d19f6cdbef6a3553bf04bf92bdde2746854301796894cdfcb63a5d110ce4e83d2ea9fccbbdd08a78274ff90158dcd88820b6619dcd9f42fb8855aad5c8ef6331d28bb96466ca636f8d25f304897bdd860013e6745bf9ed56a3e7cc45bfc3bf55b1f45b5d7ba9363420107a6db1b96f3eb4ebe89571e3214092e90b8d10fa9da2008aba29eadf2dbbe36c8f688d1cdb75e76f42c665d96cdad6167994a129aa9dbf9804d5f15514b87b7af2f20b179468181fdd2dbc4751b222a2f9f167979aebc2666bcebdd49390821ee0ebffd6ec8f9f8c2fb0e3b4dd9bb1fcc601760b4c290665603ed61d93d691ad6e6c54f7f4fb419d9ca1c78a8ec0dda625899c29018617f9aa5cbea42f45dd22ec23441263b92d92295b071d6ee35b4274c39e573da6b1cbf2ca5470817336504dc04415ebf1e3d5ccf3e6f13437d65a51262818bb4d725ad0fce43dd4eff26138b50837c1369cd39d2141571fa335ad253b381c7252fa6910d9d10846eee3dec063a4b4cb110afad553d4b308fed6e634afa4cec30884ae2a557d08b66a87c108b43260e7bb3639a7c33762f66cb4990e319555cfc792aa30fc67a57f64a12d2c3bbf7c866b9962db7e8d634756d348d46385c4342c6d9e9e5b00c4efe659cec032cd08d7adcf97a0ac60e375dd37fe382a246f424850076639857d303e1efd0eed19595edf2ec9a9e48465893b94500954bd2b62649abf55c5324cc94288f65adbb3961e1eb008e5ec68aed882e2637cc937b17fa490fe62397fbddb3a77926676ae548f5d17f243536f97256bcbf5812538ee50b0d2a1c06aaaa0e5ba120a51e4f4107366032fb47f321888f0b0373277c42a61bad52282826c70725c3134c01aa2445362a032b3eb419f76f3f7c81677cd72ba232c00c7f673189919fa35d24c395152f4291474654fe036b76d532f70c8c940febcbe1ee908d5b53bdf10eaa874cd944aec8b874afcb78d8d38e9f62cc9cfc3431fae1eee615a24397299daf77bb6e2b3229991698e3e6d7d06f980e9741b0e77520f6ef65861f45fa4e34d49dc28d9992c3270862ca3de614053706e4074f8364957075d73902f7dfce18a419cf8770c899464f96ef427b96eefe6fefdafcc310595ad94483f04c932bb690509e8d021b8c41a1703eb98559f5fa6ef97f156e2ea6cd157c25d828c3fd5e0cc2832f2f789333ac7a4939c4008c99e2ebaef4659448eb25c4dcefaa1c31429fa3ec7cc126c0082bb6c6e2d30673e907c326c05823754284fe6b0c20aac13519d100e8fb398c64b38be3ce55b240eb4ae61adf7dfcb6062882cb96f8dfd2e141c9d8d73babe8a46b61f2ccd0e6e4dba90e97c43ede0efaa2631e974ac74d4d8ec3e03377ac12d60a29bf3e65fce2545f5ce136f5c99271322b1b51b1933b3cbf32e12e081d7c4fb9eec10c72930390fc3b488c85a5e8dad873e87863ce7df61d47c6b11ef4c5a09bbbf9bcd08ad7a6dad85c37e7b4e9d055dccab93fbfb2f8d588309fc2487980a038f1cf566c766bf674b89aebf6cc5d72c535359b266394eaec4880f7295313da8b73e8b3a50da76dab16993dda8e31aee322f7b913c5b85985965d7fdf31742e2417f55551237e899ab6d562e5c540f3054286552ce89daa7a8ad3e8b9423c9614a2f594b3e858d6ec6e8d8e609e281d20a1c08a7e2e56f5e3ff23e16411cf9c473b6e36eb84f2eff2d1b02f3409c1ee56dda90db12210b057030124e0af68f88467c834e1b53da2722ae0e2deeddb922e6113ad7144fcd1143017a8b5c10317de01eacf3f0038d84d2ef8eb8869829bd5b6e464b0a45df4a92c183e058d5a52db7ebb09984d57948fc66d4d70042e7eea184abdc1d679073e1e9be41c1d3022587b8989a068b876fbd6a06682090c4a4c0cdcb2444a094ffe7ed9760f3c6a80660f53f92f87603d43d2334e7713d6cf162c789c34717f10611572bfde50ca090e75520ac33effd7671ec5192b8b76a74e8b7476cc410299af9d66f5f6e1585f7bbe9924802dbe8e8977ec69ecd4100c5de4b1881878125b1ef548f925ba6aa82da9deb803d9d6e5255b90d237b0ab782c97854e414cde39073a8154f0950c9926d2ee6dc9a94bbee2fcd1acb89c76354de515dd76ad124d5f4c06c126a595283fbbbee6eb931acf051c501192ffbc630056f396448cb2fb96203809830d57428f2b44037762bd443b932a8709ae83a2f09155d1d271c964ad3e43c565c7c88f157e7834bc277c700bef8a40547cd7199bb62a559cf33446f627654f19c7ea19698d1908f7873e448479911bd7192a3c147608b725375efe0f5a0103d30b6869990f164235ebf01d7724d5ed1b867110cbd634eac5166633ec57c22f16ef267dd6a389b9e9aef9c8f4e2b450f1e3dd8886bf15a5c97e15120e43b4b48348c1eda0e7f83501171b3ff41593cfad2c41fc4085391a6d6101c2ba593588b366b65d921bed0eadd5e73a239a947bad09fea2bf812cb9c50a04dc1f48fd373deae2f22fbad27da3c3d09fed6e58d88f8de19295c965b17dbaf7f215cf629fc72a5cd9362de6a3b77eed29b5fb03ce76b1d018e0337eb61337ca0c3ab3c571e4119f2cc81133b95321acf5769b7a16d7d8fffbf1b7de4a21f3226e698384cf7e384783ca29c8baf312c1ca907fc77f0fe8bf62f5f78b358f23387f"

        /** PQ hash-based signing pubkey — SLH-DSA-SHA2-256s (FIPS 205)
         *  SPKI hex. Diverse PQ assumption against ML-DSA's lattice. */
        const val SLHDSA_PUBKEY_HEX = "3050300b0609608648016503040318034100f8a3025ec6164b73463954167cb4d59ba5673ecd18c32786a8f1a369de02996fa78736edc57ea46baa0333cb6772a14a7eb187b48b2fe88a5052f5b2e0241c25"
    }

    init {
        if (Security.getProvider("BC") == null) {
            try {
                val klass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                val provider = klass.getDeclaredConstructor().newInstance() as java.security.Provider
                Security.addProvider(provider)
            } catch (t: Throwable) {
                Log.w(TAG, "BC provider registration failed: $t")
            }
        }
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
                    // Redact: log only the first 8 hex chars of each
                    // side. A full hash is itself a forensic artifact
                    // (it identifies precisely which model bytes were
                    // expected and which arrived — useful for an
                    // attacker correlating download attempts).
                    Log.w(TAG, "$id sha256 mismatch (manifest claim): expected=${expectedHex.take(8)}… actual=${actualHex.take(8)}…")
                    continue
                }
                // Second-layer pin: the in-code ModelBundle.pinFor()
                // pin must also match if it is not the TBD sentinel.
                // This is the "compromised-signer" defense — a hostile
                // signer with all four manifest keys can re-issue the
                // existing models but cannot swap in hostile bytes.
                val codePin = ModelBundle.pinFor(id)
                if (codePin != null && !actualHex.equals(codePin, ignoreCase = true)) {
                    Log.w(TAG, "$id sha256 mismatch (in-code pin): expected=${codePin.take(8)}… actual=${actualHex.take(8)}…")
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

    /**
     * Fetch the manifest wrapper, verify ALL FOUR signatures, return
     * the parsed body. Wrapper format:
     *
     *     {
     *       "body":           "<base64 canonical JSON>",
     *       "sig_p521_b64":   "<ECDSA P-521 / SHA-512 DER>",
     *       "sig_ed448_b64":  "<Ed448 pure-EdDSA>",
     *       "sig_mldsa_b64":  "<ML-DSA-87>",
     *       "sig_slhdsa_b64": "<SLH-DSA-SHA2-256s>",
     *       "mtc_proof":      "<optional MTC inclusion proof>"
     *     }
     */
    private fun fetchAndVerifyManifest(url: String): JSONObject {
        val body = httpGet(url)
        val outer = JSONObject(String(body, Charsets.UTF_8))
        val bodyB64        = outer.getString("body")
        val sigP521B64     = outer.getString("sig_p521_b64")
        val sigEd448B64    = outer.getString("sig_ed448_b64")
        val sigMldsaB64    = outer.getString("sig_mldsa_b64")
        val sigSlhdsaB64   = outer.getString("sig_slhdsa_b64")

        val bodyBytes = android.util.Base64.decode(bodyB64,      android.util.Base64.NO_WRAP)
        val sigP521   = android.util.Base64.decode(sigP521B64,   android.util.Base64.NO_WRAP)
        val sigEd448  = android.util.Base64.decode(sigEd448B64,  android.util.Base64.NO_WRAP)
        val sigMldsa  = android.util.Base64.decode(sigMldsaB64,  android.util.Base64.NO_WRAP)
        val sigSlhdsa = android.util.Base64.decode(sigSlhdsaB64, android.util.Base64.NO_WRAP)

        // All four must verify. Ordered cheap-fast → expensive so a
        // tampered body fails quickly without the lattice / hash-tree
        // work.
        verifyEcdsaP521(bodyBytes, sigP521)
        verifyEd448(bodyBytes, sigEd448)
        verifyMlDsa87(bodyBytes, sigMldsa)
        verifySlhDsa256s(bodyBytes, sigSlhdsa)

        // MTC log-walk verifier (M10.x). The wrapper carries a
        // Sigsum-style inclusion proof of the manifest body's
        // SHA-256 in a pinned transparency log. v0.1 is
        // default-allow-on-empty: a manifest WITHOUT a proof is
        // accepted (forward-compat scaffolding); a manifest WITH a
        // proof must verify against a pinned log pubkey AND walk to
        // the claimed root. Once the project Sigsum log is in
        // production, this default flips to require-proof.
        val mtcProof = outer.optString("mtc_proof", "")
        val bodyShaHex = sha256Hex(bodyBytes)
        if (!dev.tetherand.app.crypto.MtcVerifier.verify(mtcProof, bodyShaHex)) {
            throw IllegalStateException("manifest MTC inclusion proof does not verify against any pinned Sigsum log")
        }
        if (mtcProof.isNotEmpty()) {
            Log.i(TAG, "manifest MTC inclusion proof verified against pinned log")
        }

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

    private fun verifyEcdsaP521(body: ByteArray, sig: ByteArray) {
        val pub = decodePub(P521_PUBKEY_HEX, "EC", null)
        val v = Signature.getInstance("SHA512withECDSA")
        v.initVerify(pub); v.update(body)
        if (!v.verify(sig)) throw IllegalStateException("manifest ECDSA-P521 signature does not verify")
    }

    private fun verifyEd448(body: ByteArray, sig: ByteArray) {
        val pub = decodePub(ED448_PUBKEY_HEX, "Ed448", "BC")
        val v = Signature.getInstance("Ed448", "BC")
        v.initVerify(pub); v.update(body)
        if (!v.verify(sig)) throw IllegalStateException("manifest Ed448 signature does not verify")
    }

    private fun verifyMlDsa87(body: ByteArray, sig: ByteArray) {
        val pub = decodePub(MLDSA_PUBKEY_HEX, "ML-DSA", "BC")
        val v = Signature.getInstance("ML-DSA-87", "BC")
        v.initVerify(pub); v.update(body)
        if (!v.verify(sig)) throw IllegalStateException("manifest ML-DSA-87 signature does not verify")
    }

    private fun verifySlhDsa256s(body: ByteArray, sig: ByteArray) {
        val pub = decodePub(SLHDSA_PUBKEY_HEX, "SLH-DSA", "BC")
        val v = Signature.getInstance("SLH-DSA-SHA2-256s", "BC")
        v.initVerify(pub); v.update(body)
        if (!v.verify(sig)) throw IllegalStateException("manifest SLH-DSA-SHA2-256s signature does not verify")
    }

    private fun decodePub(hex: String, algorithm: String, provider: String?): java.security.PublicKey {
        val der = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val kf = if (provider != null) KeyFactory.getInstance(algorithm, provider)
                 else KeyFactory.getInstance(algorithm)
        return kf.generatePublic(X509EncodedKeySpec(der))
    }

    fun clear() {
        outDir.listFiles()?.forEach { it.delete() }
        AiGuardRuntime.get(ctx).loadAll()
    }
}
