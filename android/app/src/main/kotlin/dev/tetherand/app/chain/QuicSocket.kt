package dev.tetherand.app.chain

import android.net.VpnService
import dev.tetherand.app.mullvad.ObfuscationBridge

class QuicSocket private constructor(private val handle: Long) : WgSocket {
    override fun send(pkt: ByteArray) {
        val rc = nativeQuicSend(handle, pkt)
        if (rc != 0) throw java.io.IOException("QUIC send rc=$rc")
    }
    override fun recv(): ByteArray = nativeQuicRecv(handle)
    override fun close() { if (handle != 0L) nativeQuicClose(handle) }

    companion object {
        init { System.loadLibrary("tetherand_wg") }
        @JvmStatic external fun nativeQuicConnect(host: String, port: Int, serverName: String): Long
        @JvmStatic external fun nativeQuicSend(handle: Long, packet: ByteArray): Int
        @JvmStatic external fun nativeQuicRecv(handle: Long): ByteArray
        @JvmStatic external fun nativeQuicClose(handle: Long)

        fun connect(bridge: ObfuscationBridge, @Suppress("UNUSED_PARAMETER") vpn: VpnService): QuicSocket {
            // For Mullvad's QUIC bridges, server_name = the certificate's SNI
            // (typically the bridge hostname). We use the bridge.host directly.
            val handle = nativeQuicConnect(bridge.host, bridge.port, bridge.host)
            require(handle != 0L) { "QUIC connect failed" }
            return QuicSocket(handle)
        }
    }
}
