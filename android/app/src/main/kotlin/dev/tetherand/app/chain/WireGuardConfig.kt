package dev.tetherand.app.chain

import android.util.Base64
import java.util.Arrays

/**
 * WireGuard configuration. Carries key material in `ByteArray`s
 * because the underlying JNI takes byte[]; we cannot use
 * `SecureBytes` for the live JNI handoff (the foreign code expects
 * the raw array). We compensate by exposing [zeroize] — the caller
 * MUST invoke it after the config has been consumed by the JNI
 * `WireGuardHop.start()` call. The pattern is:
 *
 *     val cfg = WireGuardConfig.parse(text)
 *     try { hop.start(cfg) } finally { cfg.zeroize() }
 *
 * After `zeroize()` the key arrays are full of zeros and the config
 * is no longer usable.
 */
data class WireGuardConfig(
    val privateKey: ByteArray,            // 32 bytes
    val address: String,                  // e.g. "10.66.0.2/32"
    val dns: List<String>,
    val peerPublicKey: ByteArray,         // 32 bytes
    val presharedKey: ByteArray?,         // 32 bytes or null
    val allowedIps: List<String>,         // e.g. ["0.0.0.0/0"]
    val endpointHost: String,
    val endpointPort: Int,
    val persistentKeepaliveSecs: Int = 0,
    /** M4f: how the wire packets are obfuscated. Default plain UDP. */
    val obfuscation: dev.tetherand.app.mullvad.ObfuscationMode = dev.tetherand.app.mullvad.ObfuscationMode.Plain,
    /** M4f: for SS / udp2tcp / QUIC, the bridge endpoint to dial INSTEAD of (endpointHost, endpointPort). */
    val obfuscationBridge: dev.tetherand.app.mullvad.ObfuscationBridge? = null,
    /** M4e: enable DAITA traffic shaping on this hop. */
    val daita: Boolean = false,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WireGuardConfig) return false
        return constantTimeEq(privateKey, other.privateKey) &&
            address == other.address &&
            dns == other.dns &&
            constantTimeEq(peerPublicKey, other.peerPublicKey) &&
            constantTimeEqNullable(presharedKey, other.presharedKey) &&
            allowedIps == other.allowedIps &&
            endpointHost == other.endpointHost &&
            endpointPort == other.endpointPort &&
            persistentKeepaliveSecs == other.persistentKeepaliveSecs
    }
    override fun hashCode(): Int = address.hashCode() * 31 + endpointHost.hashCode()

    /**
     * Wipe all key material in place. Idempotent. After this call the
     * config object still exists but the key arrays are zeroed; any
     * subsequent use will hand the JNI a useless config (rejected
     * by the noise-protocol handshake).
     */
    fun zeroize() {
        Arrays.fill(privateKey, 0)
        Arrays.fill(peerPublicKey, 0)
        presharedKey?.let { Arrays.fill(it, 0) }
    }

    private fun constantTimeEq(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun constantTimeEqNullable(a: ByteArray?, b: ByteArray?): Boolean {
        if (a == null && b == null) return true
        if (a == null || b == null) return false
        return constantTimeEq(a, b)
    }

    companion object {
        @Throws(IllegalArgumentException::class)
        fun parse(text: String): WireGuardConfig {
            var section: String? = null
            val iface = HashMap<String, String>()
            val peer = HashMap<String, String>()
            for (raw in text.lineSequence()) {
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) continue
                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.substring(1, line.length - 1)
                    continue
                }
                val idx = line.indexOf('=')
                if (idx < 0) continue
                val k = line.substring(0, idx).trim()
                val v = line.substring(idx + 1).trim()
                when (section) {
                    "Interface" -> iface[k] = v
                    "Peer" -> peer[k] = v
                }
            }
            fun req(map: Map<String, String>, k: String, section: String): String =
                map[k] ?: throw IllegalArgumentException("$section.$k missing")
            fun key32(b64: String, field: String): ByteArray {
                val bytes = try { Base64.decode(b64, Base64.DEFAULT) }
                            catch (e: Exception) { throw IllegalArgumentException("$field: bad base64") }
                require(bytes.size == 32) { "$field: must be 32 bytes, got ${bytes.size}" }
                return bytes
            }
            val ep = req(peer, "Endpoint", "Peer")
            val colon = ep.lastIndexOf(':')
            require(colon > 0) { "Peer.Endpoint must be host:port" }
            return WireGuardConfig(
                privateKey = key32(req(iface, "PrivateKey", "Interface"), "Interface.PrivateKey"),
                address = req(iface, "Address", "Interface"),
                dns = iface["DNS"]?.split(",")?.map { it.trim() } ?: emptyList(),
                peerPublicKey = key32(req(peer, "PublicKey", "Peer"), "Peer.PublicKey"),
                presharedKey = peer["PresharedKey"]?.let { key32(it, "Peer.PresharedKey") },
                allowedIps = peer["AllowedIPs"]?.split(",")?.map { it.trim() } ?: listOf("0.0.0.0/0"),
                endpointHost = ep.substring(0, colon),
                endpointPort = ep.substring(colon + 1).toInt(),
                persistentKeepaliveSecs = peer["PersistentKeepalive"]?.toInt() ?: 0,
            )
        }
    }
}
