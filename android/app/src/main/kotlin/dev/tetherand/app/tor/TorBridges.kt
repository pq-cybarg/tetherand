package dev.tetherand.app.tor

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Persisted bridge configuration. Bridge lines are sensitive (some are
 * private/family bridges shared by direct request) — stored encrypted.
 */
class TorBridges(ctx: Context) {
    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-tor-bridges", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun load(): TorConfig {
        val csv = prefs.getString("bridges", "") ?: ""
        val lines = csv.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        val vanguards = prefs.getBoolean("vanguards", false)
        val preferPq = prefs.getBoolean("prefer_pq_handshake", true)
        val port = prefs.getInt("socks_port", 9050)
        return TorConfig(lines, vanguards, preferPq, port)
    }

    fun save(cfg: TorConfig) {
        prefs.edit()
            .putString("bridges", cfg.bridges.joinToString("\n"))
            .putBoolean("vanguards", cfg.vanguards)
            .putBoolean("prefer_pq_handshake", cfg.preferPqHandshake)
            .putInt("socks_port", cfg.socksPort)
            .apply()
    }
}
