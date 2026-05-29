package dev.tetherand.app.chain

import android.content.Context
import dev.tetherand.app.tor.TorConfig
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Tor hop backed by Arti (Rust). Loads libtetherand_tor.so on first
 * use; calls nativeInit to start the embedded arti-client; tears down
 * on stop.
 *
 * v1 ships the Arti integration + bridge config + vanguards flag +
 * PQ-NTor handshake preference. The per-flow forwarder (IP packet →
 * arti DataStream → exit-node TCP) is documented in the architecture
 * but its full implementation ships in M6.x because it reuses the
 * relay-core packet stack and needs careful UDP-vs-TCP discrimination
 * (Tor is TCP-only; UDP flows are dropped).
 *
 * caps.supportsPQ = true once Arti exposes the prop362 NTor-ML-KEM-v1
 * handshake selection knob in a release crate. Until then the
 * preference is recorded + logged but behaviourally a no-op — same
 * pattern as M10's deterministic-primary / contributory-classifier
 * separation.
 */
class TorHop(
    private val ctx: Context,
    private val cfg: TorConfig,
) : Hop {
    override val id: String = "tor"
    override val displayName: String =
        "Tor" +
        (if (cfg.vanguards) " (vanguards)" else "") +
        (if (cfg.preferPqHandshake) " · PQ" else "")
    override val caps: HopCaps = HopCaps(
        supportsPQ = cfg.preferPqHandshake,    // surface honors the user toggle
        supportsMultihop = true,               // Tor is multihop by design (3 relays minimum)
        supportsAntiCensorship = true,         // bridges + PT framework (PTs in M6.x)
    )

    private val _state = MutableStateFlow(HopState.Idle)
    override val state: StateFlow<HopState> = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats: StateFlow<HopStats> = _stats.asStateFlow()

    private var handle: Long = 0L
    private var forwarder: TorFlowForwarder? = null

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = HopState.Connecting
        try {
            System.loadLibrary("tetherand_tor")
            val cache = ctx.cacheDir.absolutePath + "/arti"
            val state = ctx.filesDir.absolutePath + "/arti"
            java.io.File(cache).mkdirs(); java.io.File(state).mkdirs()
            val bridgesCsv = cfg.bridges.joinToString(",")
            // Stage PT binaries from jniLibs into cacheDir/pts/ and
            // chmod +x. Android packs them as `.so` so the APK keeps
            // them; at runtime we rename to extension-less executables
            // so arti's spawn() finds the right binary.
            val ptStaged = PtBinaryStager.stage(ctx)
            handle = nativeInit(
                cache, state, bridgesCsv, cfg.vanguards, cfg.preferPqHandshake,
                ptStaged.ptBridge.orEmpty(),
                ptStaged.snowflake.orEmpty(),
                ptStaged.conjure.orEmpty(),
            )
            if (handle == 0L) throw IllegalStateException("Arti bootstrap failed (see logcat tetherand-tor)")
            _state.value = HopState.Connected
        } catch (t: Throwable) {
            _state.value = HopState.Error
            _stats.value = _stats.value.copy(lastError = t.message)
            throw t
        }
        // Per-flow forwarder. The dialer closure jumps into JNI to open
        // an arti circuit; the closer JNI'd nativeClose tears it down.
        // The forwarder reads packets from `input`, dispatches per-flow,
        // and emits return packets on `output`.
        val output = Channel<ByteArray>(64)
        val h = handle
        val fwd = TorFlowForwarder(
            dialer = { host, port -> nativeDial(h, host, port).toLong() },
            dialClose = { sid -> try { nativeClose(h, sid) } catch (_: Throwable) {} },
        )
        fwd.start(input, output)
        forwarder = fwd
        return output
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        try { forwarder?.stop() } catch (_: Throwable) {}
        forwarder = null
        if (handle != 0L) {
            try { nativeShutdown(handle) } catch (_: Throwable) {}
            handle = 0L
        }
        _state.value = HopState.Idle
    }

    /** Reachability probe — dials host:port through Tor. Returns true
     *  on circuit success. UI uses this to sanity-check connectivity. */
    fun probe(host: String, port: Int): Boolean {
        val h = handle
        if (h == 0L) return false
        return nativeDial(h, host, port) == 0
    }

    /** Snapshot of forwarder counters for the UI. */
    fun counters(): FlowCounters = forwarder?.let {
        FlowCounters(it.tcpFlowsOpened.get(), it.tcpFlowsClosed.get(), it.udpDropped.get(), it.nonIpDropped.get())
    } ?: FlowCounters()

    data class FlowCounters(
        val tcpFlowsOpened: Long = 0,
        val tcpFlowsClosed: Long = 0,
        val udpDropped: Long = 0,
        val nonIpDropped: Long = 0,
    )

    private external fun nativeInit(
        cacheDir: String, stateDir: String, bridgesCsv: String,
        vanguards: Boolean, preferPq: Boolean,
        ptBridgePath: String, snowflakePath: String, conjurePath: String,
    ): Long
    private external fun nativeDial(handle: Long, host: String, port: Int): Int
    private external fun nativeClose(handle: Long, streamId: Long): Int
    private external fun nativeShutdown(handle: Long)
}
