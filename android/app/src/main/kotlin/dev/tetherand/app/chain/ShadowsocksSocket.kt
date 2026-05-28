package dev.tetherand.app.chain

import android.net.VpnService
import dev.tetherand.app.mullvad.ObfuscationBridge

class ShadowsocksSocket private constructor(private val handle: Long) : WgSocket {
    override fun send(pkt: ByteArray) {
        val rc = nativeSsSend(handle, pkt)
        if (rc != 0) throw java.io.IOException("SS send rc=$rc")
    }
    override fun recv(): ByteArray = nativeSsRecv(handle)
    override fun close() { if (handle != 0L) nativeSsClose(handle) }

    companion object {
        init { System.loadLibrary("tetherand_wg") }
        @JvmStatic external fun nativeSsConnect(host: String, port: Int, cipher: String, password: String): Long
        @JvmStatic external fun nativeSsSend(handle: Long, packet: ByteArray): Int
        @JvmStatic external fun nativeSsRecv(handle: Long): ByteArray
        @JvmStatic external fun nativeSsClose(handle: Long)

        fun connect(bridge: ObfuscationBridge, @Suppress("UNUSED_PARAMETER") vpn: VpnService): ShadowsocksSocket {
            val cipher = bridge.cipher ?: error("Shadowsocks bridge missing cipher")
            val password = bridge.password ?: error("Shadowsocks bridge missing password")
            val handle = nativeSsConnect(bridge.host, bridge.port, cipher, password)
            require(handle != 0L) { "shadowsocks connect failed" }
            return ShadowsocksSocket(handle)
        }
    }
}
