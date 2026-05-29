package dev.tetherand.app.nym

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Encrypted-at-rest persistence for the zk-nym mnemonic + gateway choices.
 * Mnemonic is the most sensitive — losing it means losing paid bandwidth.
 */
class NymCredentials(ctx: Context) {
    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-nym", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun load(): NymConfig = NymConfig(
        mnemonic = prefs.getString("mnemonic", "") ?: "",
        entryGateway = prefs.getString("entry_gateway", "") ?: "",
        exitGateway = prefs.getString("exit_gateway", "") ?: "",
    )

    fun save(cfg: NymConfig) {
        prefs.edit()
            .putString("mnemonic", cfg.mnemonic)
            .putString("entry_gateway", cfg.entryGateway)
            .putString("exit_gateway", cfg.exitGateway)
            .apply()
    }
}
