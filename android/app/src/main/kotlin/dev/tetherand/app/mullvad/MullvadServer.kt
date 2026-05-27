package dev.tetherand.app.mullvad

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MullvadWgServer(
    val hostname: String,
    @SerialName("country_code") val countryCode: String,
    @SerialName("city_code") val cityCode: String,
    val active: Boolean,
    val owned: Boolean,
    @SerialName("ipv4_addr_in") val ipv4: String,
    val pubkey: String,
    @SerialName("multihop_port") val multihopPort: Int = 0,
) {
    val display: String get() = "$hostname  ($countryCode-$cityCode)${if (owned) " 🛡" else ""}"
}

@Serializable
data class MullvadRelays(
    val wireguard: MullvadWgList,
)

@Serializable
data class MullvadWgList(
    @SerialName("port_ranges") val portRanges: List<List<Int>> = emptyList(),
    val relays: List<MullvadWgServer>,
)
