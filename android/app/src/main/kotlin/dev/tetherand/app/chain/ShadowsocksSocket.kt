package dev.tetherand.app.chain

import android.net.VpnService
import dev.tetherand.app.crypto.SecureBytes
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

        /**
         * Connect to the Shadowsocks bridge.
         *
         * Caveat on the password: the Mullvad API returns the SS
         * shared password as a JSON string, so by the time it reaches
         * this method it is already interned on the JVM heap as a
         * `String` — which cannot be wiped reliably. We do a
         * best-effort reflection wipe of the `String` value field
         * immediately after the JNI handoff (the Rust side has by
         * then copied the bytes into a zeroize'd buffer). That
         * narrows but does not close the window during which the
         * password is recoverable from a heap dump.
         *
         * The properly-paranoid fix is to change the Mullvad
         * deserialization path to produce a `CharArray` instead of
         * a `String`; that's a v0.2 work-item.
         */
        fun connect(bridge: ObfuscationBridge, @Suppress("UNUSED_PARAMETER") vpn: VpnService): ShadowsocksSocket {
            val cipher = bridge.cipher ?: error("Shadowsocks bridge missing cipher")
            val password = bridge.password ?: error("Shadowsocks bridge missing password")
            val handle = try {
                nativeSsConnect(bridge.host, bridge.port, cipher, password)
            } finally {
                // Narrow the heap-residency window for the password.
                // Best-effort: works on most JVM internals; no-ops if
                // the field layout differs.
                SecureBytes.bestEffortWipeString(password)
            }
            require(handle != 0L) { "shadowsocks connect failed" }
            return ShadowsocksSocket(handle)
        }
    }
}
