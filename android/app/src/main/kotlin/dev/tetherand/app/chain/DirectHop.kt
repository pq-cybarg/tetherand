package dev.tetherand.app.chain

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Passthrough hop. Forwards packets unmodified. Reserved for chains that
 *  need a terminal "exit" element (e.g. [Tor] → Direct → internet).
 *  M3's single-WG chain doesn't use this — WG sends UDP directly to its
 *  peer — but the type ships built and tested for M4+. */
class DirectHop(override val id: String = "direct", override val displayName: String = "Direct") : Hop {
    override val caps = HopCaps()
    private val _state = MutableStateFlow(HopState.Idle)
    override val state = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats = _stats.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        val out = Channel<ByteArray>(capacity = 256)
        _state.value = HopState.Connected
        job = scope.launch {
            try {
                for (pkt in input) {
                    out.send(pkt)
                    _stats.value = _stats.value.copy(
                        txBytes = _stats.value.txBytes + pkt.size,
                        rxBytes = _stats.value.rxBytes + pkt.size,
                    )
                }
            } finally { out.close() }
        }
        return out
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        job?.cancel(); job = null
        scope.cancel()
        _state.value = HopState.Idle
    }
}
