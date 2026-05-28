package dev.tetherand.app.splittunnel

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SplitTunnelStore(ctx: Context) {
    private val masterKey = MasterKey.Builder(ctx)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx,
        "tetherand-split-tunnel",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun disallowed(): Set<String> = prefs.getStringSet("disallowed", emptySet()).orEmpty()

    fun setDisallowed(pkgs: Set<String>) {
        prefs.edit().putStringSet("disallowed", pkgs).apply()
    }
}
