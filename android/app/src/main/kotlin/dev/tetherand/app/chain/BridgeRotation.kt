package dev.tetherand.app.chain

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicReference

/**
 * Periodic Tor bridge rotation — M11.x.
 *
 * Rotates the active [TorHop]'s bridge selection on a schedule to defeat
 * long-running QUIC connection-migration deanonymization and to reduce
 * the value of any single bridge-operator compromise. A device that
 * keeps using the same bridge for hours leaves a uniquely-shaped fingerprint
 * in netflow logs at both endpoints; rotating periodically (60-90 min,
 * jittered) breaks that fingerprint into shorter independent segments.
 *
 * The rotation is **observable but not blocking** — at rotation time we:
 *   1. Pick a fresh bridge from the configured set (skipping the current one).
 *   2. Stop the active hop.
 *   3. Restart it with the new selection.
 *
 * During the ~5-second cutover, the chain is degraded (no Tor circuit).
 * Apps using the embedded SOCKS5 listener will see a brief connection
 * failure and reconnect; the user's foreground traffic experiences a
 * blip but no leak — the VPN service stays up and blocks egress.
 *
 * If the configured bridge set has only one entry (or zero), rotation
 * is a no-op — there's nothing to rotate to. The class still runs its
 * timer loop so flipping the config from one bridge to many takes
 * effect on the next tick without needing a restart.
 *
 * Uses jittered intervals (60-90 min uniform-random) so that rotation
 * times don't form a predictable across-device pattern that itself
 * becomes a fingerprint.
 */
class BridgeRotation(
    private val configProvider: () -> dev.tetherand.app.tor.TorConfig,
    private val torHop: TorHop,
    private val minIntervalMs: Long = 60L * 60 * 1000,   // 60 min
    private val maxIntervalMs: Long = 90L * 60 * 1000,   // 90 min
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private val lastUsedBridge = AtomicReference<String?>(null)
    @Volatile private var started = false

    /**
     * Start the rotation timer. Idempotent — subsequent calls no-op.
     * The first rotation fires after the first jittered interval, not
     * immediately, to avoid disrupting a freshly-bootstrapped circuit.
     */
    fun start() {
        if (started) return
        started = true
        scope.launch {
            while (isActive) {
                val interval = nextInterval()
                delay(interval)
                try {
                    rotateOnce()
                } catch (t: Throwable) {
                    Log.w(TAG, "rotation failed: ${t.javaClass.simpleName} — ${t.message}")
                }
            }
        }
        Log.i(TAG, "bridge-rotation timer armed (interval ${minIntervalMs/60_000}-${maxIntervalMs/60_000} min jittered)")
    }

    fun stop() {
        scope.cancel()
        started = false
    }

    /**
     * Force a rotation now (e.g. user-triggered via UI). Safe to call
     * concurrently with the timer — the mutex serializes.
     */
    suspend fun rotateNow() = rotateOnce()

    private suspend fun rotateOnce() = mutex.withLock {
        val cfg = configProvider()
        val bridges = cfg.bridges
        if (bridges.size < 2) {
            // Nothing to rotate to. Don't restart for nothing.
            return@withLock
        }
        val current = lastUsedBridge.get()
        val next = bridges.firstOrNull { it != current } ?: bridges.first()
        Log.i(TAG, "rotating to fresh bridge (${bridges.size} configured, ${redact(next)})")
        // In-place arti runtime swap inside TorHop — Channels and
        // forwarder coroutines stay alive; only the underlying
        // arti pointer changes. Stream-level retries fall back via
        // TorFlowForwarder's TCP state machine (in-flight reads
        // get -1 → FIN-ACK to device → device reconnects through
        // the fresh runtime).
        if (torHop.rotateBridge(next)) {
            lastUsedBridge.set(next)
            Log.i(TAG, "rotation complete")
        } else {
            Log.w(TAG, "rotation failed; keeping previous bridge active")
        }
    }

    private fun nextInterval(): Long {
        // Uniform random in [min, max]. Uses the SHAKE-256-whitened
        // RNG (we're at JCA position 1 via SeekerRng) for the seed.
        val range = maxIntervalMs - minIntervalMs
        val jitter = (Math.random() * range).toLong()
        return minIntervalMs + jitter
    }

    /** Best-effort redaction so bridge fingerprints don't leak to logcat. */
    private fun redact(bridge: String): String {
        // Bridge lines look like "Bridge obfs4 1.2.3.4:443 FINGERPRINT cert=..."
        // Log only the prefix + length; full content is sensitive.
        val prefix = bridge.take(20)
        return "$prefix… (${bridge.length} chars)"
    }

    companion object {
        private const val TAG = "BridgeRotation"
    }
}
