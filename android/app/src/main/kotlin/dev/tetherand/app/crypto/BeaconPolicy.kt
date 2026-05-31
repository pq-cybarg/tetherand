package dev.tetherand.app.crypto

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * User policy for `PublicBeacons` egress.
 *
 * Default posture is **Tor-only** (`clearnetFallback = false`): if no
 * Tor circuit is up, beacon fetches are deferred. Polling drand /
 * NIST from a stable source IP every minute is a unique fingerprint
 * that lets either operator (or anyone with netflow visibility) track
 * Tetherand installs across networks, so we refuse to leak that
 * signature by default.
 *
 * Some users — those who do not have Tor available at all, or those
 * who consider the beacons' contribution to the SHAKE-256 mixer more
 * valuable than the IP leak it would cost — can flip the toggle to
 * allow a clear-net fallback. The toggle is surfaced on the AI tab.
 *
 * Stored in `EncryptedSharedPreferences` so the choice survives
 * across launches but is wiped by `HardenedModeManager.enter()`
 * (along with everything else, to restore strict posture at the
 * start of a high-risk session).
 */
class BeaconPolicy(ctx: Context) {

    private val prefs by lazy {
        val mk = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        EncryptedSharedPreferences.create(
            ctx, FILENAME, mk,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    /**
     * If true, `PublicBeacons` will fall back to clear-net (direct
     * connection to api.drand.sh / beacon.nist.gov, pinned TLS but no
     * Tor) when no Tor circuit is available. Defaults to false.
     */
    var clearnetFallback: Boolean
        get() = prefs.getBoolean(KEY_CLEARNET_FALLBACK, false)
        set(value) {
            prefs.edit().putBoolean(KEY_CLEARNET_FALLBACK, value).apply()
        }

    /** Wipe the policy (called by HardenedModeManager.enter()). */
    fun clear() { prefs.edit().clear().apply() }

    companion object {
        private const val FILENAME = "tetherand.beacon_policy"
        private const val KEY_CLEARNET_FALLBACK = "clearnet_fallback"

        @Volatile private var INSTANCE: BeaconPolicy? = null
        fun get(ctx: Context): BeaconPolicy = INSTANCE ?: synchronized(this) {
            INSTANCE ?: BeaconPolicy(ctx.applicationContext).also { INSTANCE = it }
        }
    }
}
