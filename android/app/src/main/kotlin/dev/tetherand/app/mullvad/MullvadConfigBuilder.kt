package dev.tetherand.app.mullvad

import android.util.Base64
import dev.tetherand.app.chain.WireGuardConfig

object MullvadConfigBuilder {
    private const val MULLVAD_DNS = "10.64.0.1"
    private const val DEFAULT_WG_PORT = 51820

    init { System.loadLibrary("tetherand_wg") }

    /** Returns 64 bytes (priv[0..32] + pub[32..64]). */
    @JvmStatic external fun nativeGenerateX25519Keypair(): ByteArray

    /** Drive the full Mullvad provisioning flow and return a ready-to-use WireGuardConfig. */
    suspend fun build(
        api: MullvadApi,
        accountNumber: String,
        server: MullvadWgServer,
    ): Pair<WireGuardConfig, MullvadDevice> {
        val login = api.login(accountNumber)
        val kp = nativeGenerateX25519Keypair()
        require(kp.size == 64) { "native keypair returned ${kp.size} bytes" }
        val privKey = kp.copyOfRange(0, 32)
        val pubKey = kp.copyOfRange(32, 64)
        val pubB64 = Base64.encodeToString(pubKey, Base64.NO_WRAP)
        val device = api.registerDevice(login.accessToken, pubB64)

        val serverPub = Base64.decode(server.pubkey, Base64.DEFAULT)
        require(serverPub.size == 32) { "server pubkey not 32 bytes" }

        val cfg = WireGuardConfig(
            privateKey = privKey,
            address = device.ipv4_address,
            dns = listOf(MULLVAD_DNS),
            peerPublicKey = serverPub,
            presharedKey = null,
            allowedIps = listOf("0.0.0.0/0"),
            endpointHost = server.ipv4,
            endpointPort = DEFAULT_WG_PORT,
            persistentKeepaliveSecs = 25,
        )
        return cfg to device
    }
}
