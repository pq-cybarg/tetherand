package dev.tetherand.app.threat.heuristic

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Per-device suppressions for heuristics whose default behaviour is
 * security-correct but conflicts with a known-acceptable workflow on
 * this particular device.
 *
 * Example: `AdbdNetworkSurface` correctly flags every device with
 * adb-over-Wi-Fi enabled, because that surface is the CVE-2026-0073
 * RCE vector. But for a developer who deliberately enabled it for
 * their own debug workflow on a trusted network, the alert is noise.
 * The developer suppresses it once; the detector then stops firing
 * for that signal on this device.
 *
 * Suppressions are scoped per-detector via a string key. They live in
 * EncryptedSharedPreferences so they survive reboot but the file is
 * encrypted at rest and can't be read out by another app.
 *
 * Hardened Mode entry can optionally CLEAR all suppressions (so the
 * conference posture is strict). That hook ships in M9.x.
 */
class ThreatSuppressions(ctx: Context) {

    companion object {
        const val KEY_ADBD_NETWORK = "suppress:adbd_network_surface"
        const val KEY_PATCH_STALE  = "suppress:patch_level_staleness"
    }

    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-threat-suppressions", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun isSuppressed(detectorKey: String): Boolean = prefs.getBoolean(detectorKey, false)

    /** Suppress this detector on this device. Records the timestamp
     *  so the UI can show "suppressed since YYYY-MM-DD" rather than
     *  a featureless boolean. */
    fun suppress(detectorKey: String) {
        prefs.edit()
            .putBoolean(detectorKey, true)
            .putLong("${detectorKey}:ts", System.currentTimeMillis())
            .apply()
    }

    fun unsuppress(detectorKey: String) {
        prefs.edit()
            .remove(detectorKey)
            .remove("${detectorKey}:ts")
            .apply()
    }

    fun suppressedSinceMs(detectorKey: String): Long =
        prefs.getLong("${detectorKey}:ts", 0L)

    fun clearAll() {
        prefs.edit().clear().apply()
    }
}
