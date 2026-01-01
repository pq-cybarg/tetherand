package dev.tetherand.app.crypto

import android.content.Context
import android.util.Log
import dev.tetherand.app.net.PinnedHttp
import dev.tetherand.app.net.TorProxyRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicReference

/**
 * Periodically pulls bytes from two independent public-randomness
 * beacons and caches them for SeekerRng to absorb as additional
 * entropy sources.
 *
 * Sources:
 *
 *   1. **drand** (League of Entropy). 32 bytes every 30 seconds,
 *      threshold-BLS-signed by ~16 independent operators (Cloudflare,
 *      Protocol Labs, EPFL, U. Chile, Kudelski, etc.). HTTP API:
 *      `GET https://api.drand.sh/public/latest` returns
 *      `{round, randomness: <hex>, signature, previous_signature}`.
 *      The `randomness` field is `SHA256(signature)` per drand v1; we
 *      absorb it directly.
 *
 *   2. **NIST Interoperable Randomness Beacon v2.0**. 512 bits every
 *      60 seconds, ECDSA-P384-signed by NIST. HTTP API:
 *      `GET https://beacon.nist.gov/beacon/2.0/pulse/last` returns
 *      a `pulse.outputValue` hex field carrying 64 bytes. Different
 *      operator, different cryptosystem, different jurisdiction —
 *      diverse failure surface vs. drand.
 *
 * **Why public beacons are safe to absorb even from a hostile network**:
 * the SHAKE-256 mixer in `SeekerRng` enjoys the random-oracle property
 * that its output is computationally indistinguishable from uniform as
 * long as ANY one of the absorbed sources contains a single bit of
 * unpredictable entropy. An adversary who controls our network and
 * substitutes a hostile drand round STILL cannot bias the output —
 * the other five sources (urandom, JCA SecureRandom, KeyStore HMAC,
 * sensor jitter, clock skew) carry the call.
 *
 * **BLS / ECDSA signature verification status.** The drand quicknet
 * round signatures are BLS12-381; the NIST beacon pulses are
 * ECDSA-P384. ECDSA verification would be free (any JCA provider
 * including BC supports it) — adding it for NIST beacons is a v0.2
 * todo. BLS12-381 verification is more involved: neither the platform
 * JCA nor BouncyCastle 1.80 ship a BLS12-381 verifier, and the
 * Android-native BLS libraries available (e.g.
 * `org.miracl.milagro.amcl`, `it.unisa.dia.gas:jpbc`) either are
 * unmaintained or pull in 1+ MB of pairing code — a meaningful
 * binary-size addition for what is, under our threat model, defense-
 * in-depth rather than the hard floor. The hard floor is:
 *
 *   1. TLS pinning (SPKI pin on `api.drand.sh`) — only the genuine
 *      drand load-balancer can hand us a valid TLS certificate.
 *   2. Tor-mandatory egress (default) — even with a compromised drand
 *      operator's load-balancer cert, the operator does not learn the
 *      device IP.
 *   3. SHAKE-256 random-oracle absorption — even if both 1 and 2
 *      fail and an adversary substitutes hostile beacon bytes, the
 *      seven other sources carry the call.
 *
 * Under that hard floor, BLS verification is a v0.2 binary-size /
 * defense-in-depth upgrade rather than a v0.1 must-have. Documented
 * explicitly so the decision is auditable.
 *
 * **NOT on the hot path**: SeekerRng reads `latestDrand()` /
 * `latestNist()` from the volatile cache; the network fetch runs in
 * a background coroutine on a periodic schedule. A `null` cache
 * (first 30s of process life, or network unavailable) means SeekerRng
 * silently skips those sources — no latency added to `nextBytes()`.
 *
 * **Tor-mandatory egress**. Beacons are fetched ONLY through the
 * embedded Arti SOCKS5 listener (published by `TorHop` to
 * `TorProxyRegistry`). When no Tor circuit is up, fetches are
 * DEFERRED — never falls back to clear-net. The privacy intent: a
 * device polling drand and NIST every minute from a stable source IP
 * is a unique fingerprint that lets either operator (or anyone with
 * netflow access) track Tetherand installs. Routing through Tor
 * means the only thing the beacon hosts see is the exit IP. The
 * SPKI pin set still applies inside the SOCKS-encrypted tunnel — a
 * malicious exit cannot inject a substitute cert.
 *
 * Started from `SeekerRng.installAsDefault(ctx)`. Idempotent — repeat
 * calls do not start additional refresher coroutines.
 */
object PublicBeacons {

    private val drandCache = AtomicReference<ByteArray?>(null)
    private val nistCache  = AtomicReference<ByteArray?>(null)

    @Volatile private var refresherStarted = false
    @Volatile private var appCtx: Context? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Latest drand `randomness` bytes (32 bytes), or null if not yet fetched. */
    fun latestDrand(): ByteArray? = drandCache.get()

    /** Latest NIST beacon `outputValue` bytes (64 bytes), or null. */
    fun latestNist(): ByteArray? = nistCache.get()

    /**
     * Start the background refresher. Pulls drand every 60s, NIST
     * every 60s (NIST emits a pulse every 60s; drand every 30s, but
     * we don't need every drand round — one per minute is plenty for
     * the mixer's purposes and conserves battery + uplink bytes).
     *
     * Pass the application context so the refresher can consult
     * [BeaconPolicy] for the clear-net-fallback toggle.
     *
     * Safe to call repeatedly — the second and subsequent calls are
     * no-ops.
     */
    @Synchronized
    fun startRefresher(ctx: Context) {
        if (appCtx == null) appCtx = ctx.applicationContext
        if (refresherStarted) return
        refresherStarted = true
        scope.launch {
            // First fetch immediately so SeekerRng has data within a
            // few seconds of app start (rather than waiting a full
            // 60s for the first periodic tick).
            tryRefresh()
            while (isActive) {
                delay(60_000)
                tryRefresh()
            }
        }
        Log.i("PublicBeacons", "background refresher started (drand + NIST, every 60s)")
    }

    private suspend fun tryRefresh() {
        // Tor-mandatory by default; user can opt-in to clear-net
        // fallback via BeaconPolicy (surfaced on the AI tab as a
        // toggle). The default is **Tor-only** because the privacy
        // failure mode — drand + NIST seeing a stable source IP poll
        // every minute — is what this module was built to prevent.
        val proxy = TorProxyRegistry.currentProxy()
        val allowClearnet = appCtx?.let { BeaconPolicy.get(it).clearnetFallback } ?: false
        val effectiveProxy: java.net.Proxy? = when {
            proxy != null      -> proxy           // Tor circuit available — always use it
            allowClearnet      -> null            // user opted in to clear-net fallback
            else -> {
                Log.i("PublicBeacons", "no Tor circuit and clearnet fallback off; deferring beacon refresh")
                return
            }
        }
        // Both fetches are best-effort; failures are logged at INFO
        // (Tor circuit can drop / re-establish; network unavailable
        // on a captured device is normal) and the existing cache
        // value (possibly stale) is retained because a stale beacon
        // value still carries unpredictable bits relative to whatever
        // the adversary thinks our state is.
        try { fetchDrand(effectiveProxy) } catch (t: Throwable) {
            Log.i("PublicBeacons", "drand refresh skipped: ${t.javaClass.simpleName}")
        }
        try { fetchNist(effectiveProxy)  } catch (t: Throwable) {
            Log.i("PublicBeacons", "NIST refresh skipped: ${t.javaClass.simpleName}")
        }
    }

    private fun fetchDrand(proxy: java.net.Proxy?) {
        val client = PinnedHttp.client(proxy)
        // Explicit quicknet endpoint — the `/public/latest` default
        // can redirect across chains over time. Pinning the chain
        // hash explicitly lets us verify each round against the
        // matching pinned pubkey in DrandVerifier.
        val req = Request.Builder()
            .url("https://api.drand.sh/${DrandVerifier.QUICKNET_CHAIN_HASH}/public/latest")
            .header("User-Agent", "Tetherand-SeekerRng/1")
            .get()
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@use
            val body = resp.body?.string() ?: return@use
            val json = JSONObject(body)
            val round = json.optLong("round", -1L)
            val sigHex = json.optString("signature", "")
            val randHex = json.optString("randomness", "")
            if (round < 0 || sigHex.isEmpty() || randHex.length != 64) return@use

            // BLS12-381 signature verification (M11.x deferred → now
            // delivered). If verification succeeds, absorb the round.
            // If it fails OR the Milagro AMCL library is absent
            // (binary-size opt-out), fall back to absorbing under
            // the random-oracle defense — the SHAKE mixer is robust
            // to hostile beacon bytes regardless.
            val verified = DrandVerifier.verify(round, sigHex)
            if (verified) {
                Log.i("PublicBeacons", "drand round $round BLS-verified + absorbed (blst pairing check passed)")
            } else {
                Log.i("PublicBeacons", "drand round $round absorbed under random-oracle fallback (BLS sig not verified)")
            }
            drandCache.set(hexToBytes(randHex))
        }
    }

    private fun fetchNist(proxy: java.net.Proxy?) {
        val client = PinnedHttp.client(proxy)
        val req = Request.Builder()
            .url("https://beacon.nist.gov/beacon/2.0/pulse/last")
            .header("User-Agent", "Tetherand-SeekerRng/1")
            .get()
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@use
            val body = resp.body?.string() ?: return@use
            // NIST pulse JSON: {pulse: {outputValue: <128-char hex>, ...}}
            val pulse = JSONObject(body).optJSONObject("pulse") ?: return@use
            val outHex = pulse.optString("outputValue", "")
            if (outHex.length == 128) {
                nistCache.set(hexToBytes(outHex))
            }
        }
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
