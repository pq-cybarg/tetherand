package dev.tetherand.app.hardened

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class HardenedModeStore(ctx: Context) {
    private val masterKey = MasterKey.Builder(ctx)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx,
        "tetherand-hardened",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    var active: Boolean
        get() = prefs.getBoolean("active", false)
        set(value) { prefs.edit().putBoolean("active", value).apply() }

    var enteredAtMs: Long
        get() = prefs.getLong("entered_at_ms", 0L)
        set(value) { prefs.edit().putLong("entered_at_ms", value).apply() }

    /** Pre-conference attestation JSON blob. */
    var preSnapshotJson: String?
        get() = prefs.getString("pre_snapshot_json", null)
        set(value) { prefs.edit().putString("pre_snapshot_json", value).apply() }

    var postSnapshotJson: String?
        get() = prefs.getString("post_snapshot_json", null)
        set(value) { prefs.edit().putString("post_snapshot_json", value).apply() }

    /** Frozen app-audit baseline — the set of trusted packages at Hardened
     *  Mode entry. Drift alerts compare against this. */
    var appBaselineJson: String?
        get() = prefs.getString("app_baseline_json", null)
        set(value) { prefs.edit().putString("app_baseline_json", value).apply() }
}
