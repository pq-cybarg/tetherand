package dev.tetherand.app.hardened.selfie

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * On-disk store for failed-unlock-attempt selfies + the metadata
 * needed to surface them in the Threat tab.
 *
 * JPEGs land under `context.filesDir/selfies/<epoch_ms>.jpg`. The
 * directory itself sits inside the app's private data dir, which on
 * Android is sandboxed away from other apps and from MediaStore
 * indexing. Combined with the device's userdata encryption, the
 * images are at rest behind the keyguard the same way Signal's
 * media folder is.
 *
 * Per-attempt counters + the enable toggle live in
 * EncryptedSharedPreferences so the running attempt-counter cannot
 * be tampered with by another app that gets temporary access.
 */
class SelfieStore(private val ctx: Context) {

    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-selfies", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
    private val dir: File = File(ctx.filesDir, "selfies").also { it.mkdirs() }

    /** Master enable for the selfie-on-fail-unlock feature. False by
     *  default; the user opts in by tapping the toggle on the Threat
     *  tab AND granting Device-Admin via Settings. */
    var enabled: Boolean
        get() = prefs.getBoolean("enabled", false)
        set(value) { prefs.edit().putBoolean("enabled", value).apply() }

    /** Running count of consecutive failed unlock attempts since the
     *  last successful unlock. Surfaced in the alert summary. */
    val count: Int get() = prefs.getInt("attempts", 0)

    fun incrementCount(): Int {
        val n = count + 1
        prefs.edit().putInt("attempts", n).apply()
        return n
    }

    fun resetCount() { prefs.edit().putInt("attempts", 0).apply() }

    /** Persist a JPEG; returns the file path on success, null on
     *  write failure. Filename uses ISO timestamp so the directory
     *  listing is human-sortable. */
    fun save(jpeg: ByteArray): String? {
        return try {
            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.ROOT)
                .format(Date(System.currentTimeMillis()))
            val f = File(dir, "$stamp.jpg")
            f.writeBytes(jpeg)
            f.absolutePath
        } catch (_: Throwable) { null }
    }

    /** All saved selfies, newest first. UI uses this to populate the
     *  Hardened-tab gallery. */
    fun list(): List<File> = dir.listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()

    fun clearAll() {
        dir.listFiles()?.forEach { it.delete() }
        resetCount()
    }
}
