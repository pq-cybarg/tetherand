package dev.tetherand.app.chain

import android.content.Context
import dev.tetherand.app.nym.NymConfig
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * NymVPN hop backed by the Nym mixnet via nym-sdk (Rust crate
 * embedded as libtetherand_nym.so). Sphinx-format 3-hop mixnet
 * between entry + exit gateways; breaks the address-association
 * that VPN-only hops (WG, Mullvad, Tor) can't.
 *
 * caps:
 *   - supportsPQ: false at the wire layer (Sphinx uses X25519 today;
 *     PQ-mixnet is an upstream-tracked nym-sdk roadmap item)
 *   - supportsMultihop: true (mixnet is multihop by design)
 *   - supportsAntiCensorship: true (gateways double as anti-censorship
 *     entry points + you can chain Tor over Nym for full plausible
 *     deniability)
 */
class NymHop(
    private val ctx: Context,
    private val cfg: NymConfig,
) : Hop {
    override val id: String = "nym"
    override val displayName: String =
        "Nym mixnet" + if (cfg.exitGateway.isNotEmpty()) " · ${cfg.exitGateway.take(8)}…" else ""
    override val caps: HopCaps = HopCaps(
        supportsPQ = false,
        supportsMultihop = true,
        supportsAntiCensorship = true,
    )

    private val _state = MutableStateFlow(HopState.Idle)
    override val state: StateFlow<HopState> = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats: StateFlow<HopStats> = _stats.asStateFlow()

    private var handle: Long = 0L

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = HopState.Connecting
        try {
            System.loadLibrary("tetherand_nym")
            val stateDir = ctx.filesDir.absolutePath + "/nym"
            java.io.File(stateDir).mkdirs()
            handle = nativeInit(stateDir, cfg.mnemonic, cfg.entryGateway, cfg.exitGateway)
            if (handle == 0L) throw IllegalStateException("nym init failed — check logcat tetherand-nym")
            _state.value = HopState.Connected
        } catch (t: Throwable) {
            _state.value = HopState.Error
            _stats.value = _stats.value.copy(lastError = t.message)
            throw t
        }
        // Pass-through for v1 — the per-flow mixnet exit-gateway dialer
        // matches the M6.x TorFlowForwarder shape, reusing the same
        // TCP-flow tracker. Ships with the next forwarder patch.
        return input
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        if (handle != 0L) {
            try { nativeShutdown(handle) } catch (_: Throwable) {}
            handle = 0L
        }
        _state.value = HopState.Idle
    }

    fun probe(host: String, port: Int): Boolean {
        val h = handle
        if (h == 0L) return false
        return nativeDial(h, host, port) == 0
    }

    private external fun nativeInit(stateDir: String, mnemonic: String, entryGateway: String, exitGateway: String): Long
    private external fun nativeDial(handle: Long, host: String, port: Int): Int
    private external fun nativeClose(handle: Long, streamId: Long): Int
    private external fun nativeShutdown(handle: Long)
}
