package dev.tetherand.app.tor

/**
 * User-tunable Tor settings persisted in EncryptedSharedPreferences.
 *
 * - `bridges`: raw BridgeDB-format lines. Sensitive; encrypted at rest.
 * - `vanguards`: enable the vanguards-style entry-guard hardening.
 * - `preferPqHandshake`: prefer PQ-NTor (prop362 / NTor-ML-KEM-v1
 *    hybrid) handshake when upstream Arti supports it. Default on.
 * - `socksPort`: local SOCKS5 listener (M6.x will surface this for
 *    bridging non-VPN apps).
 */
data class TorConfig(
    val bridges: List<String> = emptyList(),
    val vanguards: Boolean = false,
    val preferPqHandshake: Boolean = true,
    val socksPort: Int = 9050,
)
