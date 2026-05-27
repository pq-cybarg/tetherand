package dev.tetherand.app.chain

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ChainState { Idle, Starting, Active, Stopping, Error }

/** Wires a sequence of [Hop]s end-to-end. */
class ChainOrchestrator(private val hops: List<Hop>) {
    private val _state = MutableStateFlow(ChainState.Idle)
    val state: StateFlow<ChainState> = _state.asStateFlow()

    private var tunBound: Channel<ByteArray>? = null
    val tunBoundOutput: Channel<ByteArray>? get() = tunBound

    suspend fun start(tunInput: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = ChainState.Starting
        try {
            require(hops.isNotEmpty()) { "chain must have at least one hop" }
            var current = tunInput
            for (h in hops) {
                current = h.start(current)
            }
            tunBound = current
            _state.value = ChainState.Active
            return current
        } catch (t: Throwable) {
            _state.value = ChainState.Error
            stop()
            throw t
        }
    }

    suspend fun stop() {
        _state.value = ChainState.Stopping
        for (h in hops.reversed()) {
            try { h.stop() } catch (_: Throwable) {}
        }
        tunBound?.close()
        tunBound = null
        _state.value = ChainState.Idle
    }
}
