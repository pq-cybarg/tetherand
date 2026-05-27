package dev.tetherand.app.mullvad

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MullvadLoginRequest(
    @SerialName("account_number") val accountNumber: String,
)

@Serializable
data class MullvadLoginResponse(
    @SerialName("access_token") val accessToken: String,
    val expiry: String,
)

@Serializable
data class MullvadDeviceRegisterRequest(
    val pubkey: String,
    @SerialName("hijack_dns") val hijackDns: Boolean = true,
)

@Serializable
data class MullvadDevice(
    val id: String,
    val name: String,
    val pubkey: String,
    val ipv4_address: String,
    val ipv6_address: String? = null,
    val created: String,
)
