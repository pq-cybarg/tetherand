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
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004c54c3a62c76a3e971f7cb42dd6c39040882fe9818eea6d7e0374dfd8390f279b67ded087385814ac8d5dcc15613dadbce596434633f3eca9b95fe2ecc360cc2b"

        /** Post-quantum signing pubkey — ML-DSA-87 in X.509/SPKI DER form,
         *  hex-encoded. ~5228 hex chars (2614 raw bytes). NIST PQC Level 5
         *  ("comparable to AES-256"). */
        const val MLDSA_PUBKEY_HEX =
            "30820a32300b060960864801650304031303820a210039ee1f7adc48c9cb3662c3fa581bd0946572ed0b382d09713745109ddad5d9b19a1807583b7c8eff51154176825f5929670173f49fc173900084d2bf4ec19dde2de7da71e43add6aac20d93b147e47e04d23958ef642605845f3b3a3958066d6cb82c27fa0fb41936c810efa9e0770d0b2f464e8480d6acd551026ac1127681ba7144590bce3542a1e85c7c962b880921bc0a23ecc6681c3a972e442fc89c4106bba45caf66a53fe76612ddb9a5d83d1bb2d07aaed8f9a7b50e6da5969fa36cf0592dc94fd2b8126f0d710eb72ce20dadfaa271019cc81765feef9d140b90affe022fc45570dcb26341e3cb53873d3cf94e8aa2efbddde66e515de25a67c84ee1ea333cfcbf7257aa57ec89a72a68cc0f82ca6a504582f9f3fd827819e1f462b23a7f1cc3f02eb9f4ea0453f4f706ffae0b9512c599cd9b1379c01494f1d704e54a6fe6b12182e4105f47702a038cc5d0eb41fc175e4eee7ceba8abb8631fe41e24a32a513d3f22c84dbea34deda365d06ae944dceb32a0b131cd98db098dd451f64280c16f43eb1304df05311e474f48c4d9250667466ec575c975563818f944e3f0264599bf7124125679c22042fff66ed46471e4c5fb72a3b2aa63bf93b44b2d2412533a33838b5efca8f7302130abfb6865ec4cbe6432885ebe095d86c0c8e5307675b9b91cb7264e1de56d7e98d447049fd99465c128de213f0483bd377aae5b61e9e43c2a87608003fe36b1168ba8b16e9e9141b36fae3a4d90d3049dd674b5ec215ce3e7d319343e2d3da7f7b0a3e4cf24c5aa1ac195fecfc038c804be3ffbb657f17bbdb4255e58400bca1351d093f83dc4071d789ddc4db295698d2be767a7afe3dabbbbde4466d79f4c559de2378f0e661b4c558c2d38c4eb6f23afb781034d8990ae4244fe2e16dd00918d842f2ab2ce67bc14e6b6d736443724ab57e66bf44badab0f2e6fa291f021b280b08b9b8a137d62579d630cd4e680c8859e26a72e43fcc5b4352d9653dc548d73de0acf5183b07b9fbdbcf595f8942bb9aa7252b1cad8d22f70137602fc4c9473563d14d207c9cf1f4116f1830d319d2f9b17f849c0fefbf41edd9a334081af8b487c7f8cde7fdd7453257e5200171e134cb223d274e42890598b8540b2852383bd0e0d41032ec293c8e3fb6d82ef763d655a1ddf96c97a7296d46bba099d85d8b4643b251ff5bd8c9b1dbd7a75d9a785230dd3daf8a41e2bf3772cad6cf39d636d708d84c0451b1ca5058b8c4b544ede4e3b8184c19d5de2ef2ef21d3afa9df0ee7549468563af474248471147f2b94373ad4a9257163aa1c4f978a8895686ac0f5d1c4fd0c0432b65d49383afc960ab3425bba5087a180f366df714993e416897c4572e7918c6a302e6e34219cbc5b16343be0349240cd8e63c867e4dd657df6803be6f7f00e0219848f632b1ec4a9abdd6f5790e2165e65d970ce7020b52817b3fa09f6f2d15eaac1b4d7c4012f330deb4185b9ca96cbc153f60a96de87af8b604c2b4dc2ae133e46bcbf126123091dcebc8fdc39e8db8b42c8ac7574d696b014089e955bb21bb22870d5f9101296b91ea48ef19fb3bff2d7a88893e77c7372be35947135efcd1fb6e67013bc1a0bad4a760a74ad8299e19837f05ed1aed1e24619df74b5ddfb22d9068274d5b882bfd3973e71b010cf33b9fb6862e96a80c615c3ca18a1fc69644e88183d30c984c122c1cfcfdf83c8313b52bc961138c56175f4002fca0f29c2f880394d38158640bc7d85a8d4d76a939c7335086cca41d62f0086d38d3118ab344b52f3f35b7bea2aaba4456e8b7d9411717057be6ac9565050b6b07756fbeeec7f84e407db96f09d0e0a8dad0b19bf3ecb7039e28d348570165833ba675bf1985574eb8296ba3fc431f29a0fe1d764725294012f8acc6f355fa3042f131fcb39e8149f2ab8bc90bbadf152af33402020040a73faeaa752e34041cf0bd7b85a807e0f1ef21b830e46b24bc4e0e9e1f656ee78a207741e5bd0b49eae463817a535c8733d696b04288cec07f0cd8909a586601801d9f565fb4d7fe5b1db694890e58da2eeb10364e7cf5e3a9730ca45b888471aa15732e455bead7d6176d43c344d826e16921ed76818549687e84a6101a7b5e7406e507e37b9ecf5e922edfb3b2e5e5805588f71a33af190ff0637592096e0112830c5695ba2ac72e98c556b67428c5abc5feb4efa08ac563cf414e8bd4c4191ae4d9af290ef933be39b49c8e4c65017ce9a7ef9a4f1de65025ae3c5c3b5b0d0d291af468762054857b473c8509299197725e12dd075f90dde293553a9eb6abf00968febc161cd31433d70df269b787149e77a302c29cd255157a834e7c572f81ed5aaf2201fcc472d6f71ea6316f8167275ccca16bbc725f0d95a6eb5a968081566e0dd758f7c51bbc63b6524244e729520502f0f06ea5a88658ab746ee950633d67b98cc388ca71e609656bec0e99416c383cd0d2c286cf95973d7b5acd9fc05c6f585c12134ca85fa452dbc915116ac3a604fc4b17e242ea7527f7468dff6b165257ab03a3f6ba0dc94549e21b2ab4a3af3e164e7ba5cc59907635fb4d3e59dfff8f5ff0a774fc4a0aeb758b5e33566b4f0fc5d22415d840b3b4b2184fd1ef126bb999fd8747b366d269587b653d0e86513cc2437f5fcfe92db1f74b1683c12e5db923aca53189353b68a01ece20d63d23b7d0b1774fa95081550932f372ef6f11c686a0f193ac9f033c09be64715423014100c213349c2f9e1f12a690f2b1fa2a4f00c3c6116480c9b225e21b34fdda04a39323ce1352221c43fb1fb34e87d89c5eb28da5d1d47c2eccc5af2df215ea80f66a8e9e89c6c2aef90580fa299556461184f0179d16a2825cda6f3ccc9bfd5b84f0bce2a5abd7755c559ab81d72535175e9564b52a2176081f19a38b669ba40f2cb8c1fcdcd64eb83dbd0716d2dfb20d0b729ec04569a1f0191a211c1f63b5c2a0e9c8264862b44a0e7433aea76fccb214d006e900df9a65aa319393da8be9282042763244417a96997760dc903bc86b11e40e1a7f77577954ab4ef009d0d3a4216b7c18dbed5b327c58d01b81a30a08d64e4dfcdb5cb5ec4d7fb27fcf3e7263a2ce6dd85fcd2666b15d6168aa8849584d090a5e51b9cb0c1de439a57412b38910686e82836577820b10aedaff8c42a75e2e6b1b12072566a4fc51fe71fc1d11dc913a41da743cb3d0aa5f61e679e4c0e5c741b166b62ee61d65d1af37fbf13d530cfcc0f46d0b965971f7b99e252020cc6bd87853f2e0b118712dd176c5556cf4208b68da84e7da56fe24f5707c4872275914e48197ec874e6b25d3451b8dc8def4253a7b8946b6af8816118208f7ca8deb49ceec30e4b102b3a4c7fbfbce1e0657628e23cb82b7b5cc2b526a8df0fd05bae96a2df52fedc6c4af989e12d4a774cc760f88cfb7e7b97525014e456fe4745fec0aeec2be4648774eeb5712a7ab64857e49c81046cfb7be8c55ffd0a663c7d8d9619c4eb63fb9e5b1a62237de290cb8c62d136ce0728be6d5aa73874acd4e60aa20448580233411af702bb26e65c091d8cd318776ef11066e9e23254080a47c5d6c00b654d0fd623ab74918bf6bc81b593ea8579263773fcb3c22d8e930cb7a12197b950b0a8b8eb1d43292b18bbe"
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
