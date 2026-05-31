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
    private var wgSock: WgSocket? = null
    private var daitaHandle: Long = 0
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

            wgSock = buildSocket()

            // DAITA: allocate if requested.
            if (config.daita) {
                val machines = dev.tetherand.app.mullvad.DaitaMachines.load(vpnService).toTypedArray()
                if (machines.isNotEmpty()) {
                    daitaHandle = nativeDaitaNew(machines)
                    Log.i(TAG, "DAITA enabled with ${machines.size} machine(s)")
                } else {
                    Log.w(TAG, "DAITA requested but no machines bundled — running without")
                }
            }

            val out = Channel<ByteArray>(capacity = 256)
            output = out

            // TUN-bound packets → WG encap → wgSock send
            jobs += scope.launch {
                for (pkt in input) {
                    handleAction(nativeEncap(handle, pkt), out)
                    if (daitaHandle != 0L) emitDaitaActions(nativeDaitaOnSent(daitaHandle, pkt.size), out)
                }
            }
            // wgSock recv → WG decap → next hop / TUN-bound out
            jobs += scope.launch {
                while (isActive) {
                    try {
                        val frame = wgSock!!.recv()
                        if (frame.isEmpty()) continue
                        _stats.value = _stats.value.copy(rxBytes = _stats.value.rxBytes + frame.size)
                        handleAction(nativeDecap(handle, frame), out)
                        if (daitaHandle != 0L) emitDaitaActions(nativeDaitaOnRecv(daitaHandle, frame.size), out)
                    } catch (e: java.net.SocketTimeoutException) {
                        // expected on UDP socket; loop drives the timer
                    } catch (e: Throwable) {
                        if (isActive) Log.w(TAG, "wgSock recv: $e")
                        break
                    }
                }
            }
            // WG timer tick
            jobs += scope.launch {
                while (isActive) {
                    delay(250)
                    handleAction(nativeUpdateTimers(handle), out)
                }
            }
            // DAITA tick
            if (daitaHandle != 0L) {
                jobs += scope.launch {
                    while (isActive) {
                        delay(50)
                        emitDaitaActions(nativeDaitaTick(daitaHandle), out)
                    }
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

    private fun buildSocket(): WgSocket = when (config.obfuscation) {
        dev.tetherand.app.mullvad.ObfuscationMode.Plain -> {
            val sock = DatagramSocket()
            require(vpnService.protect(sock)) { "VpnService.protect() failed for UDP" }
            sock.connect(InetSocketAddress(config.endpointHost, config.endpointPort))
            sock.soTimeout = 1000
            PlainUdpSocket(sock)
        }
        dev.tetherand.app.mullvad.ObfuscationMode.UdpOverTcp -> {
            val bridge = config.obfuscationBridge ?: error("UDP-over-TCP needs a bridge endpoint")
            val tcp = java.net.Socket()
            require(vpnService.protect(tcp)) { "VpnService.protect() failed for TCP" }
            tcp.connect(InetSocketAddress(bridge.host, bridge.port), 10_000)
            tcp.soTimeout = 1000
            UdpOverTcpSocket(tcp)
        }
        dev.tetherand.app.mullvad.ObfuscationMode.Shadowsocks ->
            ShadowsocksSocket.connect(config.obfuscationBridge!!, vpnService)
        dev.tetherand.app.mullvad.ObfuscationMode.Quic ->
            QuicSocket.connect(config.obfuscationBridge!!, vpnService)
    }

    private fun handleAction(rawAction: ByteArray, outChannel: Channel<ByteArray>) {
        if (rawAction.isEmpty()) return
        val tag = rawAction[0].toInt() and 0xff
        val payload = rawAction.copyOfRange(1, rawAction.size)
        when (tag) {
            0 -> {} // Done
            1 -> { // SendToPeer
                try {
                    wgSock?.send(payload)
                    _stats.value = _stats.value.copy(txBytes = _stats.value.txBytes + payload.size)
                } catch (e: Throwable) {
                    Log.w(TAG, "wgSock send: $e")
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

    /** Apply scheduled DAITA actions: padding packets get encrypted through
     *  WG and sent; block actions are logged (the M4 MVP doesn't enforce). */
    private fun emitDaitaActions(raw: ByteArray, out: Channel<ByteArray>) {
        if (raw.size < 4) return
        val bb = java.nio.ByteBuffer.wrap(raw).order(java.nio.ByteOrder.BIG_ENDIAN)
        val n = bb.int
        for (i in 0 until n) {
            if (bb.remaining() < 5) break
            val tag = bb.get().toInt() and 0xff
            val arg = bb.int
            when (tag) {
                1 -> {
                    // SendPadding: encapsulate a zero-filled buffer of `arg`
                    // bytes (capped to 1500) and emit. The peer decrypts and
                    // discards (the inner "IP packet" is malformed).
                    val dummy = ByteArray(arg.coerceIn(1, 1500))
                    handleAction(nativeEncap(handle, dummy), out)
                }
                2 -> Log.d(TAG, "DAITA block ${arg}ms (not enforced in MVP)")
            }
        }
    }

    /** Replace the BoringTun handle with one keyed by PSK; restart pumps. */
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
        val sock = wgSock ?: throw IllegalStateException("wgSock gone")
        jobs += scope.launch {
            while (isActive) {
                try {
                    val frame = sock.recv()
                    if (frame.isEmpty()) continue
                    handleAction(nativeDecap(handle, frame), out)
                } catch (e: java.net.SocketTimeoutException) {
                } catch (e: Throwable) {
                    if (isActive) Log.w(TAG, "wgSock recv (post-rekey): $e")
                    break
                }
            }
        }
        jobs += scope.launch {
            while (isActive) {
                delay(250)
                handleAction(nativeUpdateTimers(handle), out)
            }
        }
    }

    override suspend fun stop() {
        _state.value = HopState.Stopping
        jobs.forEach { it.cancel() }
        jobs.clear()
        try { wgSock?.close() } catch (_: Throwable) {}
        wgSock = null
        output?.close()
        output = null
        if (handle != 0L) { nativeFree(handle); handle = 0 }
        if (daitaHandle != 0L) { nativeDaitaFree(daitaHandle); daitaHandle = 0 }
        // Wipe Kotlin-side key material now that the JNI WG instance
        // (which held its own copies in Rust) has been freed. The Rust
        // side wipes its copies via the zeroize crate; this finishes
        // the job on the JVM heap.
        try { config.zeroize() } catch (_: Throwable) {}
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

        @JvmStatic external fun nativeDaitaNew(machines: Array<ByteArray>): Long
        @JvmStatic external fun nativeDaitaOnSent(handle: Long, size: Int): ByteArray
        @JvmStatic external fun nativeDaitaOnRecv(handle: Long, size: Int): ByteArray
        @JvmStatic external fun nativeDaitaTick(handle: Long): ByteArray
        @JvmStatic external fun nativeDaitaFree(handle: Long)
    }
}
