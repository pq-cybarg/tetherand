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
 * `textguard-v1` + `qrguard-v1`, ~2.4 GB compressed) does not ship in
 * the APK — it would bloat the APK past Play's size limits and would
 * be obsolete the moment the model files re-train. Instead the
 * bundle ships as a separate signed download fetched through whatever
 * privacy chain the user has active.
 *
 * # Signature posture — hybrid classical + post-quantum
 *
 * The manifest is signed twice:
 *
 *   1. **ECDSA P-256** over SHA-256 against the pinned `ECDSA_PUBKEY_HEX`.
 *   2. **ML-DSA-87** (NIST PQC FIPS-204 / Module-Lattice-DSA at security
 *      Level 5) against the pinned `MLDSA_PUBKEY_HEX`.
 *
 * Both signatures must verify or the manifest is rejected. An attacker
 * needs to forge BOTH a classical and a lattice signature on the same
 * body — defeating either both a Q-classical cryptanalysis breakthrough
 * AND a quantum-computer signing attack. The classical signature is
 * the load-bearing one today; the PQ signature is the insurance.
 *
 * Note: this is **stricter than the IETF composite-sigs draft**
 * (`draft-ietf-lamps-pq-composite-sigs`), which pairs ECDSA-P256 with
 * **ML-DSA-44** (Level 2, ~AES-128 equivalence). We pin Level 5 because
 * the threat model is "harvest-now-decrypt-later against a key that
 * signs once and is verified for a decade" and the bandwidth cost of
 * the larger PQ signature (~4.6 KB vs ~2.4 KB) is negligible against
 * a multi-GB model download. When the IETF composite draft is
 * finalized the wrapper format below can grow the composite OID
 * encoding alongside the current split fields without a breaking
 * verifier change.
 *
 * # Transparency hook — Sigsum / Merkle-of-Trust
 *
 * The manifest wrapper also carries an optional `sigsum_proof` field
 * — a Merkle inclusion proof against a public, witness-co-signed log.
 * When populated, a third verification step checks that the manifest
 * body's hash actually appears in the public log, defeating an
 * attacker who *steals* both signing keys and signs a malicious
 * manifest only for one specific victim. Witnesses are independent
 * third parties that co-sign log tree heads; even compromising the
 * log operator doesn't get you past the witness signatures.
 *
 * v1 ships the surface; the actual log submission + proof verify
 * lives behind the `sigsum` feature flag below and ships next.
 *
 * # Keygen
 *
 *     openssl ecparam -name prime256v1 -genkey -noout \\
 *       -out keys/aiguard-signer-ecdsa.pem
 *     openssl ec -in keys/aiguard-signer-ecdsa.pem -pubout \\
 *       -outform DER -out keys/aiguard-signer-ecdsa.pub.der
 *     openssl genpkey -algorithm ML-DSA-87 \\
 *       -out keys/aiguard-signer-mldsa.pem
 *     openssl pkey -in keys/aiguard-signer-mldsa.pem -pubout \\
 *       -outform DER -out keys/aiguard-signer-mldsa.pub.der
 *
 * # Signing a manifest
 *
 *     bash scripts/sign-manifest.sh \\
 *       keys/aiguard-signer-ecdsa.pem \\
 *       keys/aiguard-signer-mldsa.pem \\
 *       manifest-body.json > dist/manifest.json
 *
 * # Hard properties
 *
 *   - The HTTP fetches use the system-default HttpURLConnection, which
 *     respects the active VpnService. If the user has a privacy chain
 *     up, every byte goes through it. There is no out-of-band path.
 *   - Both signatures MUST verify. There is no fallback to a single
 *     algorithm. A manifest with only one signature is rejected.
 *   - Each model file's SHA-256 is checked against the manifest value
 *     before the bytes hit disk — defeats partial-write corruption
 *     from a circuit drop mid-download.
 */
class ModelUpdater(private val ctx: Context) {

    companion object {
        private const val TAG = "AiGuardModelUpdater"

        const val MANIFEST_URL = "https://aiguard.tetherand.dev/v1/manifest.json"

        /** Classical signing pubkey — ECDSA P-256 in X.509/SPKI DER form,
         *  hex-encoded. ~91 hex chars. */
        const val ECDSA_PUBKEY_HEX =
            "3059301306072a8648ce3d020106082a8648ce3d030107034200046308b9d94767033ed68e404d5e907374351acec1a1154aca557751f5f3f0e9793e4a350e5a12f31329a2631ef507c817410fb60705e3f44628db6b8d93960351"

        /** Post-quantum signing pubkey — ML-DSA-87 in X.509/SPKI DER form,
         *  hex-encoded. ~5228 hex chars (2614 raw bytes). NIST PQC Level 5
         *  ("comparable to AES-256"). */
        const val MLDSA_PUBKEY_HEX =
            "30820a32300b060960864801650304031303820a210007727d9b07e8e187116861032ef81b0097aa153c198ebf98244e836385b0a8cfcfd3554b9683b5a55c9716b8a689ccca0b51df8be298a9ade93b27223f6e3cfe037178e4210b0c1513716a23faed5e479ab869263f5e4265355c2903b1bcc3b3ee451e025c49b7ee9b454ee7c1452fa156631584cba2654467f470788d1b948e88efef00caaf87b158b7d22aba935418a24de3fd46a46ed956d0a27c75e01429e545057330419f89f2b0911ca63edc5537411b679817fc2479f2c4deea442b29dc726ca7805a8c4a8dd588af4e3b9f077a938aad5f0b100c0840dfb00bc3cd5bdf7a51adf07767af87cfb68e31f6020705078f1f406b8f249f41285bb7c8ab3a5c14d306efe0cbedde20e3b96fb0f66cf737bf4251af2332e6b05d348fa644f7cbc084c72dc798c18805c5a3414b11be906e942e768ae9dea8b031b20301d3cfa83c9e5e9c41db6f429467764d26953b3373bd186f5d8d2f00ae6cbd34a588c66ccf5c4672852a1d17e954f021758d9214d574515edbdef278763eef3e70efc78674fb182d11d1937ca599def066ad5d7d2a07ec099078114da8b0b97cb2ef13739371ad57c299e5aa310fa03a07dde2d2ef19e1181e8f99fe33d834b49d02e6a53ba875a02d6fa039d8219f90ca7b0c48a6ee988badc9a9ddc130a79be7037799f5f12c035207d3e4f1fe7e6bb6ff1e10151a172f70d946ff447cb4bdc58a6e391b457c53a59d904c04dcfb4f1495b8076851880112504c533ad21d8078a572df805344b2df83a53a3c3f78fc65ce90e8983185592f1f7f92cf515d5db224300f9ef9204b9557824d0eb7b70252402c2e0ba409a7d6beca91fdedd7008b4a775aae1511578c4d80ff08ba60ca34819fb1c181419382d9fa3b8e24092eaa49bd9a9d79ad4bea16b72a14ff6c3e5b13da418e7e6d5cf70aa65d5021f959c5227b1c61d61b08d45d5f723bc41a3305cd382041bd39d4421fee88d3dfffef5455aa4c91e155b9979c69d6f8d1822dfda650b81266953d17f0257e749046a0ab42296c89bf5b0ae51adccd89157e04d26e18537eea2e487a36c819e7fe53cafb4ec765f02b5cc2454fa94e8beeb7960cc002605a5a7953f21a97fa6e7874ef939c79c7cd00d58da1e7785107f392e822b55468abc41abd5bb6d1911c784d90c08e34beb1d49b5b43b4a5984711594e127dbf6c8ae28a1e31e2305cd0d9b513f5d2d594ecc4b8ddefb3b66587f6a5ea9e4689030bb421c78d01367885a943dd1e99a0e8b230724667719139d2cc222b9e39ed7ff761dcb3b1468b0640d6596a40c0b7217135ada2f96e2acd3c71a86058ecda66626231571ca2df53fce01f2739a0e30bf54b4dc4bd092a511ad6eb146965b85f56266eb9744b7b10e11ec2c4b9d02d7a2ebf41c59ae8836fb56e1ae1b6ae641cec6e8d4744df15b749cc5cdf8d9d8266bba41c982b4059cac6603d82cf66b21102a78b5bfafbf7f75cc9185f332123c6378d244b7ce6d8523a561bea6664048d315b9701bf92bf4a9af1f5c60d96efa672f506a427f914d4df581846cf37d86543e705601d98dc5601e4415a044a600a7e32ac2c17e63350cc9e61ec6e9b3fa3a4a0f5f366fd96acffdf065beeb65110c1cacd5e8d0f68f8329ddc42d8b2480ae3e6b6af9f50c33e231b13dcbf3967b2e41016be812ae725baaa230ff0f65d61a5f8c7919666a787913bf1a5d9477834636c50669027746abefa65930d2d523c10d19f8f214d82d142cc90f3641c9603f357925c2d93fa7935a430f648ec817c30b7f63202881e685abaa5eb0664444b95c21b19f30ce7c8f683dc9d806279315177ffea3766699e5570a6753d6dbd49881e3bb44d3f86d9f679a77bfcaf3a4641aa495cb9dd122f656740cf4d767dbb0a909a58e22fa938eea69588f7c10ab4810d2ed11668bf26dcb5ff36b51508ad61685152b481413f00cdcaf6ee0e19c82d32db0a98fe3ba81abcc879847988e381788b3b7b4660d4434021703c95151cb6855d757f98c1c856103730e8d5f5adb99f8a95b668f2dd0de8bb67fedd9612af362d0e55f6196ca27f2531f55d64215dd8d6a88b5ed744a6bc87c71b8ce32873cfcc7e94e42a55384964f4291a16a8de9e31df76278f34379cb2c852726c1b41ef1446ecc7385695c7243826564c8d5f1123fcc454c7f04246889c751c2896c770e76f82f1a7f6488fe68b6be0d309c60357a88cc8b4fb596e9e7ba039e179230586f41a1d3a1eacdf9dab90418251c756db29b9f7992522dc3a897dde5ac45f75255b633abd06d7da8da6255b7b19bd9b53ad9f9ef279b58a42a6d75c0a26b508dee4b6efd9820debd6ed818e5e7b62142a5ae35873cbaca9ecfa66c96568d401f064632f60d3edd7387d54bd794d24d60b509e6e841925199e1c9d6106874d0b8e3d3b0d4b00b69fe2e14b5d6984d0a8f91b6be3634eb6a747dae3952c4496e6b6c8215c1a70d57ff46743e4d8733867a34a6cb576cbf391809980698cb1f3c443bdd1bbf879a054b3be6bd05881d617321eea815a2ba660441baf0b6015691c72656ff53b860bd813af91d36bd68e8e047003b0ed7d7224e306c1ddd1d4944fe89a32492a80f399e8f49a134e7dfff39989777a3d62eb42b19a08460fc2e7a6785006a00ad19c57bfc100a97e57c4fe9f4d637582a9f8a466a8bda42ce34dba9b7d4f212f9dc864cc5dc48cbde21b8845aa5e6f80972e5621426fa7a0d03221094bcf87329b0d46cf34bdaa00493fb8131602b308f59643ae757856825f74d02f27f217d3795a3a1421fa9b9826238c7ba219ae52209efce565f1415d8f2010987950f0e32ce4f403e1cfb2ee8ac66795c33fc3f16a3ae458adb1ea7166a6e44461b94da7bfdc228e63dd0bd096a751727cfe85effe788124b28a66730ab830c89480cf2d265c5db150afe1e66f88c2fd45d6d02abd988d31116be36d13166f73b64e88de92282002ca9356ba1df184060997bb01c839bb6f8ae95520efe4cb7cf506e6074ec95fb4c2cb69c4301f88ad13c2a0e94b49b8ae5a6ca8fb229c2d6666625714ab8ffb6fb229473329291e5173610c8253526723e7c657d8774774e41c75a11427d6b6409ae8edce31e27af10e87762c4bdbc1986229fe1d75b8e932d01b4dfca5315cc977753c35c84635d02d879ae7c8eef13cbf930a05d846493232926827cd3be3bab5ce9868d766cda182b76a200bc5bf0ea1263773235a7f3436f8577fed3fc00be43d5b6a9dbf6f915098643550b2189c9a5bc0907641c60d35aa9134339e3271bd66702bb2356e72022258361d1030e3ed1cd6e5eba30d79aab1c117ad0c0c9adecec6f5364f359635d80116c30a30146917cfec8c3a5167635c2ed9a94774a6a8c080f69f3b7b1d99cc2565ec77b0ecb3ea2e2547623caadacb3f1f451dd399dbef67f547d62dca60d9da31fe12b72804874c9b1ea42d7f902ef7b63d77767f6bd6befcf26d39740744a1b47d265754dec4c9c29b0e2e32fd5a87b66ee68e0c7d19a56d8f16b26b905d023fde212e40a0ebde511d43db8fd39ad2fe83337ca1acc5231700fa97add5e5a96d50d2affac44eb8aeea9fe0f3184aa4a827b6553321c1a83fcebcdb7184fc0a570742f2f29e1765ad1527ffc5cb71683bed42b9a17f030658"
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

    /**
     * Fetch the manifest wrapper, verify BOTH the ECDSA and the ML-DSA
     * signatures against the pinned pubkeys, then return the parsed
     * body. Wrapper format:
     *
     *     {
     *       "body":          "<base64 of canonical JSON>",
     *       "sig_ecdsa_b64": "<base64 of ECDSA-P256/SHA-256 DER sig>",
     *       "sig_mldsa_b64": "<base64 of ML-DSA-87 sig>",
     *       "sigsum_proof":  "<optional Sigsum log inclusion proof>"
     *     }
     */
    private fun fetchAndVerifyManifest(url: String): JSONObject {
        val body = httpGet(url)
        val outer = JSONObject(String(body, Charsets.UTF_8))
        val bodyB64       = outer.getString("body")
        val sigEcdsaB64   = outer.getString("sig_ecdsa_b64")
        val sigMldsaB64   = outer.getString("sig_mldsa_b64")

        val bodyBytes  = android.util.Base64.decode(bodyB64,     android.util.Base64.NO_WRAP)
        val sigEcdsa   = android.util.Base64.decode(sigEcdsaB64, android.util.Base64.NO_WRAP)
        val sigMldsa   = android.util.Base64.decode(sigMldsaB64, android.util.Base64.NO_WRAP)

        // Both checks must pass. Order is irrelevant cryptographically;
        // ECDSA first because it fails fast on a tampered body without
        // the larger lattice work.
        verifyEcdsaP256(bodyBytes, sigEcdsa)
        verifyMlDsa87(bodyBytes, sigMldsa)

        // Sigsum proof field is optional in v1 — when present, the
        // proof gets walked here and an inclusion-proof failure aborts
        // the update. Verifier wiring ships behind the SigsumVerifier
        // class in a follow-on commit; until then a present proof is
        // logged but not enforced.
        outer.optString("sigsum_proof", "").takeIf { it.isNotEmpty() }?.let {
            Log.i(TAG, "manifest carries Sigsum proof (${it.length} chars); verifier not yet wired")
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

    private fun verifyEcdsaP256(body: ByteArray, sig: ByteArray) {
        val pub = decodePub(ECDSA_PUBKEY_HEX, "EC")
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(pub); v.update(body)
        if (!v.verify(sig)) {
            throw IllegalStateException("manifest ECDSA-P256 signature does not verify")
        }
    }

    private fun verifyMlDsa87(body: ByteArray, sig: ByteArray) {
        // BouncyCastle exposes ML-DSA-87 as algorithm name "ML-DSA-87"
        // (BC ≥ 1.78). KeyFactory understands the X.509 SPKI we pinned.
        val pub = decodePub(MLDSA_PUBKEY_HEX, "ML-DSA")
        val v = Signature.getInstance("ML-DSA-87", "BC")
        v.initVerify(pub); v.update(body)
        if (!v.verify(sig)) {
            throw IllegalStateException("manifest ML-DSA-87 signature does not verify")
        }
    }

    private fun decodePub(hex: String, algorithm: String): java.security.PublicKey {
        val der = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val kf = if (algorithm == "ML-DSA") KeyFactory.getInstance(algorithm, "BC")
                 else KeyFactory.getInstance(algorithm)
        return kf.generatePublic(X509EncodedKeySpec(der))
    }

    fun clear() {
        outDir.listFiles()?.forEach { it.delete() }
        AiGuardRuntime.get(ctx).loadAll()
    }
}
