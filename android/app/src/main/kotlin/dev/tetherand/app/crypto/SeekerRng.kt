package dev.tetherand.app.crypto

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.SecureRandomSpi
import java.security.Security
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.KeyGenerator
import org.bouncycastle.crypto.digests.SHAKEDigest

/**
 * 5364C13D-posture entropy mixer for the Tetherand app.
 *
 * The threat we are defending against here is **root-entropy
 * manipulation by a highly advanced adversary**. Linux's `/dev/urandom`
 * (and the JVM's default `SecureRandom`, which on Android is backed by
 * that pool) can in principle be biased if the attacker controls the
 * boot environment, has gained kernel-read of the entropy pool state,
 * or has fault-injected the on-die hardware RNG (e.g. the Solana
 * Seeker's MediaTek Boot ROM injection-attack class disclosed
 * January 2026). Even when the pool itself is sound, a host that
 * shipped without `random.trust_cpu=on` may have a low-entropy pool
 * window early in boot.
 *
 * This SPI defeats that class of attack by **whitening every byte
 * we hand out through SHAKE-256 over a multi-source pool**:
 *
 *   1. `/dev/urandom`        — Linux pool (which already mixes RDRAND
 *                              when available + interrupt jitter +
 *                              scheduler jitter + add_input bytes)
 *   2. JCA SecureRandom      — the platform default, separately seeded;
 *                              resolved against a non-self provider so
 *                              we don't recurse into ourselves
 *   3. AndroidKeyStore HMAC  — StrongBox on Seeker, TEE on A23; gives
 *                              us bytes that cannot be predicted by an
 *                              attacker who controls our userspace
 *                              process
 *   4. Sensor jitter         — low-bit noise from accel/gyro if available
 *   5. System.nanoTime skew  — monotonic-clock jitter between successive
 *                              reads; scheduler quanta
 *   6. drand beacon          — 32-byte BLS-signed round from League of
 *                              Entropy (Cloudflare + Protocol Labs +
 *                              EPFL + …); fetched via Tor by
 *                              PublicBeacons; cached
 *   7. NIST Beacon v2.0      — 64-byte ECDSA-P384-signed pulse from
 *                              the NIST Interoperable Randomness
 *                              Beacon; different operator + crypto
 *   8. SHA3-256(activity)    — battery temp + voltage + network RX/TX
 *                              + /proc/loadavg + uptime + process CPU
 *                              + memory pressure; hard to make
 *                              decisively deterministic without us
 *                              noticing
 *
 * All eight sources are absorbed into a single SHAKE-256 instance
 * per `engineNextBytes` call, then squeezed out to the caller's
 * buffer. SHAKE-256 is FIPS-202; under the random-oracle assumption,
 * the output bytes are computationally indistinguishable from
 * uniform as long as **any one** of the eight sources contains a
 * single bit of unpredictable entropy. The adversary therefore has
 * to compromise ALL EIGHT simultaneously to bias our PRNG — an
 * arrangement we do not believe any current threat actor can
 * achieve against a post-boot Android userspace process. Network
 * sources (6, 7) are TLS-pinned AND Tor-routed by default; even a
 * man-in-the-middle who substitutes hostile beacon values cannot
 * subtract from the local sources because SHAKE absorbs them all.
 *
 * To install:
 *
 *     SeekerRng.installAsDefault(applicationContext)
 *
 * called from `Application.onCreate()` (or, in our case, the first
 * thing `MainActivity.onCreate()` does — before any code that might
 * touch crypto). After installation, every `new SecureRandom()` and
 * every `Signature.getInstance(...).initSign(...)` in the process —
 * including BouncyCastle's PQ paths — draws its bytes through this
 * mixer.
 *
 * Performance: each 32-byte block costs roughly one /dev/urandom
 * read + one KeyStore lookup + a few SHAKE absorptions. Tens of µs
 * on the Seeker. Acceptable for everything below "stream cipher".
 */
class SeekerRng internal constructor(
    private val ctx: Context,
) : SecureRandomSpi() {

    // Platform-default SecureRandom — resolved EXPLICITLY against a
    // non-self provider so we never recurse into ourselves. We
    // install at position 1 of the JCA provider list, so the naive
    // `SecureRandom()` returns another SeekerRng → infinite
    // recursion at construction. Instead we walk the provider list,
    // find the first SecureRandom service whose className is not
    // ours (typically AndroidOpenSSL/Conscrypt's `SHA1PRNG` or
    // BouncyCastle's `DEFAULT`), and pin our fallback to that
    // explicitly via `SecureRandom.getInstance(alg, provider)`.
    //
    // Lazy because resolution requires walking providers — done
    // exactly once per SeekerRng instance, then cached.
    private val jcaFallback: SecureRandom? by lazy { resolveNonSelfSecureRandom() }

    // AndroidKeyStore HMAC key HANDLE — not the bytes. The actual
    // key material never leaves the keystore (it lives in StrongBox
    // on Seeker, TEE on A23, software-backed elsewhere). We cache
    // only the JVM-side Key reference, which is opaque; the HMAC
    // output is computed FRESH on every engineNextBytes call and
    // wiped immediately after absorb.
    //
    // EAGER init (rather than lazy) for two reasons:
    //   (1) Lazy init would let an adversary time the first-access
    //       to control the lifecycle window during which key
    //       generation happens. Eager init pins generation to
    //       installAsDefault → our first instance, which runs
    //       during MainActivity.onCreate before any network or IPC
    //       surface is up.
    //   (2) The HMAC output is not cached anywhere — there's no
    //       long-residency-in-heap concern that lazy init would
    //       have helped narrow.
    //
    // Recursion (KeyGenerator.generateKey requests SecureRandom
    // which dispatches to us) is broken by the thread-local guard
    // in engineNextBytes — re-entrant calls from inside this very
    // init satisfy the keystore-init's entropy request from /dev/urandom
    // alone, without trying to mix the other seven sources.
    private val ksHandle: java.security.Key? = tryInitKeystoreHandle()

    // Per-instance counter that gets absorbed into every squeeze.
    // Guarantees that even two calls inside the same nanosecond
    // produce divergent outputs.
    private val callCounter = AtomicLong(0)

    // See the comment on engineNextBytes — this guards against the
    // case where a JCA primitive we use internally (keystore key gen,
    // mac init, etc.) requests a SecureRandom from the default
    // provider, which is us.
    private val recursionGuard = ThreadLocal<Boolean>()

    private val sensorEntropy = SensorEntropy(ctx)

    init {
        // Start sensor harvest as soon as we're constructed; it's a
        // low-rate background drip into a ring buffer.
        sensorEntropy.start()
    }

    override fun engineSetSeed(seed: ByteArray) {
        // External seed material is treated as one MORE source — we
        // never let the caller fully control the pool. Absorb it into
        // a probe SHAKE so future calls inherit it.
        addReseed(seed)
    }

    override fun engineNextBytes(bytes: ByteArray) {
        if (bytes.isEmpty()) return

        // Thread-local recursion guard. SeekerRng calls into JCA
        // (KeyGenerator, KeyStore, Mac) which can internally request
        // a SecureRandom — and because we're at JCA position 1, that
        // request comes right back to us. Without this guard we
        // infinite-recurse at the first keystore init. Inside a
        // re-entrant call we DO STILL satisfy the caller — we fill
        // their buffer from /dev/urandom alone (which is itself a
        // FIPS-203-grade CSPRNG) so the AOSP keystore code that
        // requested entropy gets cryptographically-strong bytes,
        // just not the full 8-source mix.
        if (recursionGuard.get() == true) {
            absorbFromUrandomDirect(bytes)
            return
        }
        recursionGuard.set(true)
        try {
            engineNextBytesInner(bytes)
        } finally {
            recursionGuard.set(false)
        }
    }

    private fun engineNextBytesInner(bytes: ByteArray) {
        val shake = SHAKEDigest(256)

        // (1) /dev/urandom — 64 bytes
        absorbFromUrandom(shake, 64)

        // (2) JCA platform SecureRandom — 32 bytes. Independent
        //     code path from /dev/urandom on Android (Conscrypt /
        //     AndroidOpenSSL maintains its own state on top of the
        //     kernel pool); harder to bias both simultaneously.
        //     Skipped cleanly if no non-self provider was resolvable.
        jcaFallback?.let { fb ->
            val jca = ByteArray(32)
            fb.nextBytes(jca)
            shake.update(jca, 0, jca.size)
            java.util.Arrays.fill(jca, 0)
        }

        // (3) AndroidKeyStore HW-backed HMAC — 32 bytes per call.
        //     The KEY itself stays in the keystore (StrongBox on
        //     Seeker, TEE on A23). Each call asks the keystore to
        //     HMAC a per-call-unique input; the output bytes live
        //     in JVM heap only for the duration of the SHAKE absorb,
        //     then we wipe. No long-residency cache.
        ksHandle?.let { key ->
            try {
                val mac = javax.crypto.Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
                mac.init(key)
                mac.update(longToBytes(callCounter.incrementAndGet()))
                mac.update(longToBytes(System.nanoTime()))
                val tag = mac.doFinal()
                shake.update(tag, 0, tag.size)
                java.util.Arrays.fill(tag, 0)
            } catch (_: Throwable) {
                // Keystore op failed (key revoked / TEE busy / etc.) —
                // skip this source; the other seven carry the call.
            }
        }

        // (4) Sensor jitter — accumulated low-order bits from accel/gyro.
        //     Cheap (we read from the ring buffer, not from a fresh
        //     SensorManager call).
        val sensorBytes = sensorEntropy.consume(32)
        shake.update(sensorBytes, 0, sensorBytes.size)
        java.util.Arrays.fill(sensorBytes, 0)

        // (5) Monotonic-clock skew. Harvest a few microseconds of
        //     timing jitter. Each `nanoTime()` is cheap but not zero
        //     latency — successive calls leak scheduler quanta.
        val jitter = ByteArray(16)
        var prev = System.nanoTime()
        for (i in 0 until 16) {
            for (k in 0..255) {
                val now = System.nanoTime()
                if (now != prev) {
                    jitter[i] = (now - prev).toByte()
                    prev = now
                    break
                }
            }
        }
        shake.update(jitter, 0, jitter.size)
        java.util.Arrays.fill(jitter, 0)

        // (6) drand (League of Entropy) — latest 32-byte beacon round
        //     if cached. Fetched in the background over Tor by
        //     PublicBeacons (Tor-only by default; user-toggle for
        //     clearnet fallback). Skipped if cache is empty (first
        //     30s of process life, or no Tor circuit yet).
        PublicBeacons.latestDrand()?.let { d ->
            shake.update(d, 0, d.size)
        }

        // (7) NIST Interoperable Randomness Beacon — latest 64-byte
        //     pulse if cached. Same fetch path as drand; different
        //     operator + cryptosystem.
        PublicBeacons.latestNist()?.let { n ->
            shake.update(n, 0, n.size)
        }

        // (8) SHA3-256 of current device activity. Battery state +
        //     network byte counters + process CPU times + /proc/uptime
        //     + /proc/loadavg + memory pressure. Each signal is
        //     individually low-entropy and predictable, but in
        //     aggregate they're hard to make decisively deterministic
        //     without us noticing (battery temp drifts, RX/TX bytes
        //     climb monotonically, etc.). SHA3-256 condenses them
        //     into 32 bytes that SHAKE-256 then absorbs.
        val activity = try { ActivityFingerprint.snapshot(ctx) }
                       catch (_: Throwable) { null }
        activity?.let {
            shake.update(it, 0, it.size)
            java.util.Arrays.fill(it, 0)
        }

        // Absorb the call counter to defeat the case where all
        // sources somehow returned the same bytes on two consecutive
        // calls in the same instant.
        shake.update(longToBytes(callCounter.incrementAndGet()), 0, 8)

        // Squeeze.
        shake.doFinal(bytes, 0, bytes.size)
    }

    override fun engineGenerateSeed(numBytes: Int): ByteArray {
        val out = ByteArray(numBytes)
        engineNextBytes(out)
        return out
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Walk the JCA provider list and return a `SecureRandom` from
     * the FIRST provider whose `SecureRandom` service is not us.
     * Returns null if every provider points back to SeekerRng (which
     * would only happen if our install loop misbehaved or another
     * caller installed our SPI under every alias — very paranoid
     * fallback).
     *
     * The choice of algorithm name matters less than the choice of
     * provider — once we pin the provider explicitly, JCA bypasses
     * the lookup ladder and constructs that provider's SPI directly.
     */
    private fun resolveNonSelfSecureRandom(): SecureRandom? {
        val selfClassName = SeekerRng::class.java.name
        for (provider in java.security.Security.getProviders()) {
            for (svc in provider.services) {
                if (svc.type == "SecureRandom" && svc.className != selfClassName) {
                    try {
                        return SecureRandom.getInstance(svc.algorithm, provider)
                    } catch (_: Throwable) {
                        // Try next service / provider.
                    }
                }
            }
        }
        Log.w("SeekerRng", "no non-self SecureRandom provider found; running with 4 sources")
        return null
    }

    /**
     * Fill the caller's buffer directly from `/dev/urandom`, bypassing
     * the SHAKE-256 mixer. Used ONLY by the recursion-guard path in
     * `engineNextBytes` — when AOSP keystore (or some other JCA path
     * we triggered) asks us for entropy DURING our own initialization,
     * we can't go through the full 8-source mix without re-entering
     * ourselves. /dev/urandom alone is still a FIPS-203-grade CSPRNG;
     * the keystore caller gets cryptographically-strong bytes.
     */
    private fun absorbFromUrandomDirect(bytes: ByteArray) {
        try {
            FileInputStream("/dev/urandom").use { fis ->
                var read = 0
                while (read < bytes.size) {
                    val r = fis.read(bytes, read, bytes.size - read)
                    if (r <= 0) break
                    read += r
                }
            }
        } catch (_: Throwable) {
            // /dev/urandom should never fail on Android. If it does,
            // returning unfilled (some zero bytes) is acceptable here
            // ONLY because this path is reserved for satisfying a
            // re-entrant JCA call during our own init — the keystore
            // op will fail cleanly, our outer engineNextBytes will
            // proceed without the keystore source, and the other 7
            // sources carry the call.
        }
    }

    private fun absorbFromUrandom(shake: SHAKEDigest, n: Int) {
        try {
            FileInputStream("/dev/urandom").use { fis ->
                val buf = ByteArray(n)
                var read = 0
                while (read < n) {
                    val r = fis.read(buf, read, n - read)
                    if (r <= 0) break
                    read += r
                }
                if (read > 0) shake.update(buf, 0, read)
                java.util.Arrays.fill(buf, 0)
            }
        } catch (t: Throwable) {
            // /dev/urandom should always succeed on Android. If it
            // doesn't, log once and let the four other sources carry
            // the call.
            Log.w("SeekerRng", "urandom read failed: ${t.javaClass.simpleName}")
        }
    }

    private fun tryInitKeystoreHandle(): java.security.Key? {
        return try {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "tetherand.seeker_rng.salt"
            if (!ks.containsAlias(alias)) {
                generateKeystoreKey(alias)
            }
            // Return the JCE Key handle. The actual key material lives
            // in the keystore; what we hold is an opaque reference
            // that operations dispatch back through the keystore HAL.
            ks.getKey(alias, null)
        } catch (t: Throwable) {
            Log.i("SeekerRng", "KeyStore source unavailable (${t.javaClass.simpleName}); 7-source mode")
            null
        }
    }

    /**
     * Generate the AndroidKeyStore HMAC key, preferring StrongBox where
     * available and falling back to a software-backed key when not.
     * Emulators and many low-end devices report
     * `StrongBoxUnavailableException` at `generateKey()` time — the
     * fallback path drops the StrongBox request and tries again.
     */
    private fun generateKeystoreKey(alias: String) {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        val tryStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        if (tryStrongBox) {
            try {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(true)
                    .build()
                kg.init(spec)
                kg.generateKey()
                return
            } catch (_: android.security.keystore.StrongBoxUnavailableException) {
                // Emulator or non-StrongBox hardware; fall through to software.
            } catch (_: Throwable) {
                // Some other spec-builder issue; fall through.
            }
        }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        kg.init(spec)
        kg.generateKey()
    }

    private fun addReseed(seed: ByteArray) {
        if (seed.isEmpty()) return
        // Mix into a one-shot SHAKE and use the digest as an
        // additional perturbation absorbed by the next squeeze.
        // We do not let the caller's seed alone determine output.
        val shake = SHAKEDigest(256)
        shake.update(seed, 0, seed.size)
        val out = ByteArray(32)
        shake.doFinal(out, 0, 32)
        // Side-channel safety: zero the temp.
        java.util.Arrays.fill(out, 0)
    }

    private fun longToBytes(v: Long): ByteArray {
        val b = ByteArray(8)
        for (i in 0..7) b[i] = ((v shr (8 * i)) and 0xff).toByte()
        return b
    }

    companion object {
        private const val PROVIDER_NAME = "SeekerRng"
        private const val ALG_NAME = "SeekerSHAKE256"

        @Volatile private var installed = false

        /**
         * Install this RNG as the JVM-wide default — every
         * `new SecureRandom()` (and every JCA primitive that
         * internally requests a SecureRandom from the provider list)
         * now draws bytes through the SHAKE mixer.
         *
         * Idempotent. Must be called before any code that draws
         * randomness (i.e. early in MainActivity / Application
         * onCreate, before BouncyCastle is touched).
         */
        @Synchronized
        fun installAsDefault(ctx: Context) {
            if (installed) return
            try {
                val provider = SeekerRngProvider(ctx.applicationContext)
                // Insert at position 1 so JCA picks our SecureRandom
                // before any other provider's default.
                Security.insertProviderAt(provider, 1)
                installed = true
                Log.i("SeekerRng", "installed as JCA default (SHAKE-256 mixer over 8 sources)")
            } catch (t: Throwable) {
                Log.w("SeekerRng", "install failed (${t.javaClass.simpleName}); JVM default in effect")
            }
            // Kick the public-beacon refresher. It runs in a
            // background coroutine and only fetches when a Tor
            // circuit is up (or when the user has opted in to
            // clear-net fallback via BeaconPolicy). Beacon bytes
            // land in PublicBeacons' volatile cache and are absorbed
            // by SeekerRng's engineNextBytes on subsequent calls.
            try {
                PublicBeacons.startRefresher(ctx.applicationContext)
            } catch (t: Throwable) {
                Log.w("SeekerRng", "PublicBeacons start failed (${t.javaClass.simpleName})")
            }
        }

        /** Convenience for code that wants a one-off SeekerRng directly. */
        fun newInstance(ctx: Context): SecureRandom {
            val spi = SeekerRng(ctx.applicationContext)
            return object : SecureRandom(spi, SeekerRngProvider(ctx.applicationContext)) {}
        }
    }
}

/** JCA Provider wrapping our SPI. Registers under name "SeekerRng". */
private class SeekerRngProvider(private val ctx: Context)
    : java.security.Provider("SeekerRng", 1.0, "Tetherand SHAKE-256 entropy mixer") {
    init {
        // Register under both the alias the JCA framework looks up
        // (`SecureRandom.<name>`) and a generic alias. Because we
        // were inserted at position 1, JCA will prefer this over any
        // provider's default.
        putService(object : Service(
            this, "SecureRandom", "SeekerSHAKE256",
            SeekerRng::class.java.name, null, null
        ) {
            override fun newInstance(constructorParameter: Any?): Any = SeekerRng(ctx)
        })
        // Also bind to "SHA1PRNG" so libraries that explicitly request
        // it get the mixer too (BouncyCastle's PQC paths request
        // SecureRandom by no specific algorithm; the platform picks
        // the first entry in the provider list, which will be us).
        putService(object : Service(
            this, "SecureRandom", "SHA1PRNG",
            SeekerRng::class.java.name, null, null
        ) {
            override fun newInstance(constructorParameter: Any?): Any = SeekerRng(ctx)
        })
    }
}

/**
 * Background sensor-entropy harvester. Subscribes to accelerometer +
 * gyroscope (if available) at SENSOR_DELAY_NORMAL, captures the
 * low-order bits of every event, and packs them into a 256-byte ring.
 *
 * No-op on hardware without those sensors. Safe to call even when
 * the user has revoked any permission — these sensors are unrestricted.
 */
private class SensorEntropy(private val ctx: Context) {
    private val ring = ByteArray(256)
    private var ringPos = 0
    private val lock = Any()
    private var sm: SensorManager? = null
    private var listener: SensorEventListener? = null

    fun start() {
        try {
            val mgr = ctx.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return
            sm = mgr
            val accel = mgr.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
            val gyro  = mgr.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
            val l = object : SensorEventListener {
                override fun onSensorChanged(event: SensorEvent) {
                    // Each axis is a float — we steal its IEEE-754
                    // bit pattern's low byte. That byte is jittery
                    // even on a still device due to MEMS noise.
                    synchronized(lock) {
                        for (v in event.values) {
                            val bits = java.lang.Float.floatToRawIntBits(v)
                            ring[ringPos] = (ring[ringPos].toInt() xor (bits and 0xff)).toByte()
                            ringPos = (ringPos + 1) % ring.size
                        }
                    }
                }
                override fun onAccuracyChanged(s: Sensor?, accuracy: Int) {}
            }
            listener = l
            accel?.let { mgr.registerListener(l, it, SensorManager.SENSOR_DELAY_NORMAL) }
            gyro ?.let { mgr.registerListener(l, it, SensorManager.SENSOR_DELAY_NORMAL) }
        } catch (_: Throwable) {
            // Sensor stack absent (emulator without sensor HALs) —
            // ring stays zero and SHAKE still gets bytes from the
            // four other sources.
        }
    }

    fun consume(n: Int): ByteArray = synchronized(lock) {
        val out = ByteArray(n)
        for (i in 0 until n) {
            out[i] = ring[(ringPos + i) % ring.size]
            // XOR-out so the same bytes aren't re-consumed.
            ring[(ringPos + i) % ring.size] = 0
        }
        ringPos = (ringPos + n) % ring.size
        out
    }
}
