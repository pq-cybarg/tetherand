package dev.tetherand.app.mullvad

/** How the WG-UDP packets are wrapped on the wire to the peer endpoint. */
enum class ObfuscationMode(val displayName: String, val nativeId: Int) {
    /** Default: plain UDP, no obfuscation. */
    Plain("UDP (none)", 0),
    /** WG-UDP frames wrapped in TCP, length-prefixed. Defeats UDP blocks. */
    UdpOverTcp("UDP-over-TCP", 1),
    /** WG-UDP encrypted with Shadowsocks AEAD, carried over TCP. */
    Shadowsocks("Shadowsocks", 2),
    /** WG-UDP carried as QUIC datagrams over UDP/443. Looks like HTTPS. */
    Quic("QUIC (UDP/443)", 3),
}

/** Per-obfuscation Mullvad bridge endpoint hint. */
data class ObfuscationBridge(
    val host: String,
    val port: Int,
    /** Shadowsocks: AEAD method (chacha20-ietf-poly1305 etc.). */
    val cipher: String? = null,
    /** Shadowsocks: shared password. */
    val password: String? = null,
)
