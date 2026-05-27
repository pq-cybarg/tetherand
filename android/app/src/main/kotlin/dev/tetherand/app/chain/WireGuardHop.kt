package dev.tetherand.app.chain

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

class WireGuardHop(
    override val id: String,
    override val displayName: String,
    private val config: WireGuardConfig,
    private val vpnService: VpnService,
) : Hop {
    override val caps = HopCaps()
    private val _state = MutableStateFlow(HopState.Idle)
    override val state = _state.asStateFlow()
    private val _stats = MutableStateFlow(HopStats())
    override val stats = _stats.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var handle: Long = 0
    private var socket: DatagramSocket? = null
    private val jobs = mutableListOf<Job>()
    private var output: Channel<ByteArray>? = null

    override suspend fun start(input: Channel<ByteArray>): Channel<ByteArray> {
        _state.value = HopState.Connecting
        try {
            handle = nativeNew(
                config.privateKey,
                config.peerPublicKey,
                config.presharedKey ?: ByteArray(0),
                config.endpointHost,
                config.endpointPort,
                config.persistentKeepaliveSecs,
            )
            require(handle != 0L) { "native wg init failed" }

            val sock = DatagramSocket()
            require(vpnService.protect(sock)) { "VpnService.protect() failed for WG socket" }
            sock.connect(InetSocketAddress(config.endpointHost, config.endpointPort))
            sock.soTimeout = 1000
            socket = sock

            val out = Channel<ByteArray>(capacity = 256)
            output = out

            // TUN-bound packets → WG encap → UDP send
            jobs += scope.launch {
                for (pkt in input) {
                    handleAction(nativeEncap(handle, pkt), out)
                }
            }
            // UDP recv → WG decap → next hop / TUN-bound out
            jobs += scope.launch {
                val buf = ByteArray(2048)
                val dp = DatagramPacket(buf, buf.size)
                while (isActive) {
                    try {
                        sock.receive(dp)
                        val frame = buf.copyOfRange(0, dp.length)
                        _stats.value = _stats.value.copy(rxBytes = _stats.value.rxBytes + frame.size)
                        handleAction(nativeDecap(handle, frame), out)
                    } catch (e: java.net.SocketTimeoutException) {
                        // expected; loop drives the timer tick
                    } catch (e: Throwable) {
                        if (isActive) Log.w(TAG, "udp recv error: $e")
                        break
                    }
                }
            }
            // Periodic timer tick
            jobs += scope.launch {
                while (isActive) {
                    delay(250)
                    handleAction(nativeUpdateTimers(handle), out)
                }
            }

            _state.value = HopState.Connected
            return out
        } catch (t: Throwable) {
            _stats.value = _stats.value.copy(lastError = t.message)
            _state.value = HopState.Error
            stop()
            throw t
        }
    }

    private fun handleAction(rawAction: ByteArray, outChannel: Channel<ByteArray>) {
        if (rawAction.isEmpty()) return
        val tag = rawAction[0].toInt() and 0xff
        val payload = rawAction.copyOfRange(1, rawAction.size)
        when (tag) {
            0 -> {} // Done
            1 -> { // SendToPeer
                try {
                    val sock = socket ?: return
                    sock.send(DatagramPacket(payload, payload.size))
                    _stats.value = _stats.value.copy(txBytes = _stats.value.txBytes + payload.size)
                } catch (e: Throwable) {
                    Log.w(TAG, "udp send error: $e")
                }
            }
            2, 3 -> outChannel.trySend(payload) // WriteToTunV4 / V6
            4 -> {
                val msg = String(payload)
                Log.w(TAG, "wg error: $msg")
                _stats.value = _stats.value.copy(lastError = msg)
            }
        }
    }

    /**
     * Replace the underlying BoringTun handle with a new one keyed by [psk].
     * Triggers a fresh WG handshake on the same UDP socket. Used by the
     * Mullvad PQ flow after the ML-KEM exchange completes.
     *
     * Note (M4 limitation): the encap-side pump (TUN→WG) requires the input
     * Channel which is held by the orchestrator, not the hop. During rekey
     * the inbound (UDP→TUN) pump and timer pump restart immediately; the
     * outbound side resumes when the orchestrator's per-hop input channel
     * carries fresh packets — which happens automatically as soon as the
     * app produces more traffic. The visible effect: a 1-2 packet pause
     * during PQ rekey.
     */
    suspend fun rekeyWithPsk(psk: ByteArray) {
        require(psk.size == 32) { "PSK must be 32 bytes, got ${psk.size}" }
        jobs.forEach { it.cancel() }
        jobs.clear()
        if (handle != 0L) { nativeFree(handle); handle = 0 }
        handle = nativeNew(
            config.privateKey,
            config.peerPublicKey,
            psk,
            config.endpointHost,
            config.endpointPort,
            config.persistentKeepaliveSecs,
        )
        require(handle != 0L) { "native wg rekey init failed" }
        val out = output ?: throw IllegalStateException("output channel gone")
        val sock = socket ?: throw IllegalStateException("UDP socket gone")
        jobs += scope.launch {
            val buf = ByteArray(2048)
            val dp = java.net.DatagramPacket(buf, buf.size)
            while (isActive) {
                try {
                    sock.receive(dp)
                    val frame = buf.copyOfRange(0, dp.length)
                    handleAction(nativeDecap(handle, frame), out)
                } catch (e: java.net.SocketTimeoutException) {
                } catch (e: Throwable) {
                    if (isActive) android.util.Log.w("WireGuardHop", "udp recv (post-rekey): $e")
                    break
                }
            }
        }
        jobs += scope.launch {
            while (isActive) {
                kotlinx.coroutines.delay(250)
                handleAction(nativeUpdateTimers(handle), out)
            }
        }
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        jobs.forEach { it.cancel() }
        jobs.clear()
        try { socket?.close() } catch (_: Throwable) {}
        socket = null
        output?.close()
        output = null
        if (handle != 0L) {
            nativeFree(handle); handle = 0
        }
        scope.cancel()
        _state.value = HopState.Idle
    }

    companion object {
        private const val TAG = "WireGuardHop"

        init {
            System.loadLibrary("tetherand_wg")
            nativeInitLog()
        }

        @JvmStatic external fun nativeInitLog()
        @JvmStatic external fun nativeNew(
            privKey: ByteArray,
            peerPub: ByteArray,
            psk: ByteArray,
            endpointHost: String,
            endpointPort: Int,
            keepaliveSecs: Int,
        ): Long
        @JvmStatic external fun nativeEncap(handle: Long, packet: ByteArray): ByteArray
        @JvmStatic external fun nativeDecap(handle: Long, packet: ByteArray): ByteArray
        @JvmStatic external fun nativeUpdateTimers(handle: Long): ByteArray
        @JvmStatic external fun nativeFree(handle: Long)
    }
}
