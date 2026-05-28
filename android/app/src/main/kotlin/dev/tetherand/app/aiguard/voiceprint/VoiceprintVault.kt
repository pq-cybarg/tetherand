package dev.tetherand.app.aiguard.voiceprint

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Encrypted persistent store of trusted caller hashes.
 *
 * Two kinds of trust:
 *   1. **Phone-number-only**: the user marked the caller as trusted,
 *      no voiceprint stored. Survives even without voiceguard-v1.
 *   2. **Voiceprint-hash**: SHA-256 of the (locally extracted)
 *      voiceprint embedding. Stored only if voiceguard-v1 is loaded.
 *
 * Anything not in this vault triggers a VerifyCallerFlow prompt in
 * Hardened Mode.
 */
class VoiceprintVault(ctx: Context) {

    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-voiceprint", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun isTrusted(phoneE164: String): Boolean = prefs.getBoolean("trust:$phoneE164", false)
    fun voiceprintHash(phoneE164: String): String? = prefs.getString("vp:$phoneE164", null)

    fun trust(phoneE164: String) { prefs.edit().putBoolean("trust:$phoneE164", true).apply() }
    fun untrust(phoneE164: String) { prefs.edit().remove("trust:$phoneE164").apply() }
    fun storeVoiceprint(phoneE164: String, hashHex: String) {
        prefs.edit().putString("vp:$phoneE164", hashHex).apply()
    }

    fun list(): List<TrustedContact> {
        return prefs.all
            .filterKeys { it.startsWith("trust:") }
            .map { (k, _) ->
                val phone = k.removePrefix("trust:")
                TrustedContact(phone, prefs.getString("vp:$phone", null))
            }
    }
}

data class TrustedContact(val phoneE164: String, val voiceprintHash: String?)
