package dev.tetherand.app.chain

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.StateFlow

enum class HopState { Idle, Connecting, Connected, Stopping, Error }

data class HopCaps(
    val supportsPQ: Boolean = false,
    val supportsMultihop: Boolean = false,
    val supportsAntiCensorship: Boolean = false,
)

data class HopStats(
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val latencyMs: Int? = null,
    val lastError: String? = null,
)

/** A unit of packet transformation in the privacy chain. */
interface Hop {
    val id: String
    val displayName: String
    val caps: HopCaps
    val state: StateFlow<HopState>
    val stats: StateFlow<HopStats>

    /**
     * Start the hop. Takes a channel of IP packets coming IN (from the
     * previous hop or the local TUN), returns a channel of IP packets
     * going OUT (toward the next hop or the terminal exit).
     */
    suspend fun start(input: Channel<ByteArray>): Channel<ByteArray>

    /** Stop the hop. Drains in-flight work. Idempotent. */
    suspend fun stop()
}
