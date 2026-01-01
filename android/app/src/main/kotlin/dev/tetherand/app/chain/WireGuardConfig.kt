package dev.tetherand.app.chain

import android.util.Base64

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
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WireGuardConfig) return false
        return privateKey.contentEquals(other.privateKey) &&
            address == other.address &&
            dns == other.dns &&
            peerPublicKey.contentEquals(other.peerPublicKey) &&
            (presharedKey?.contentEquals(other.presharedKey ?: ByteArray(0)) ?: (other.presharedKey == null)) &&
            allowedIps == other.allowedIps &&
            endpointHost == other.endpointHost &&
            endpointPort == other.endpointPort &&
            persistentKeepaliveSecs == other.persistentKeepaliveSecs
    }
    override fun hashCode(): Int = address.hashCode() * 31 + endpointHost.hashCode()

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
