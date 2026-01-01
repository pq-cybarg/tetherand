package dev.tetherand.app.nym

/**
 * NymVPN configuration. Mnemonic is the v1 "zk-nym" credential paying
 * mixnet bandwidth; if empty the SDK uses the testnet credential.
 * Gateways are nym-formatted identity strings (32-char base58 of the
 * identity public key); if empty the SDK auto-picks from the topology.
 */
data class NymConfig(
    val mnemonic: String = "",
    val entryGateway: String = "",
    val exitGateway: String = "",
)
