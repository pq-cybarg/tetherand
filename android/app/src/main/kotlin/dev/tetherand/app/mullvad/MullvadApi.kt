package dev.tetherand.app.mullvad

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class MullvadApiException(msg: String) : RuntimeException(msg)

class MullvadApi(
    private val baseUrl: String = "https://api.mullvad.net",
) {
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()
    private val jsonMedia = "application/json".toMediaType()

    suspend fun login(accountNumber: String): MullvadLoginResponse = withContext(Dispatchers.IO) {
        val body = json.encodeToString(MullvadLoginRequest(accountNumber)).toRequestBody(jsonMedia)
        val req = Request.Builder().url("$baseUrl/auth/v1/token").post(body).build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw MullvadApiException("login HTTP ${resp.code}: $txt")
            json.decodeFromString(MullvadLoginResponse.serializer(), txt)
        }
    }

    suspend fun registerDevice(token: String, pubkeyBase64: String): MullvadDevice = withContext(Dispatchers.IO) {
        val body = json.encodeToString(MullvadDeviceRegisterRequest(pubkeyBase64)).toRequestBody(jsonMedia)
        val req = Request.Builder()
            .url("$baseUrl/accounts/v1/devices")
            .post(body)
            .addHeader("Authorization", "Bearer $token")
            .build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw MullvadApiException("register-device HTTP ${resp.code}: $txt")
            json.decodeFromString(MullvadDevice.serializer(), txt)
        }
    }

    suspend fun listRelays(): MullvadRelays = withContext(Dispatchers.IO) {
        val req = Request.Builder().url("$baseUrl/app/v1/relays").get().build()
        http.newCall(req).execute().use { resp ->
            val txt = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw MullvadApiException("relays HTTP ${resp.code}: $txt")
            json.decodeFromString(MullvadRelays.serializer(), txt)
        }
    }
}
