package dev.tetherand.app.threat.heuristic

import android.os.Build
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Compare `Build.VERSION.SECURITY_PATCH` (the date string Android
 * exposes for the on-device security patch level) to today and fire
 * an alert when the device is unpatched against a meaningful window
 * of known CVEs.
 *
 * Thresholds reflect the practical reality on EoS / EoL devices like
 * the Samsung Galaxy A23 5G (SM-A236V), whose final security update
 * shipped May 2026 at the February 2026 ASB level. Any device past
 * this is incrementally exposed to every CVE published since.
 *
 *   <= 60 days:   silent (devices on the quarterly schedule are fine)
 *   60..180 days: Medium  — informational
 *   180+ days:    High    — actively exposed to multiple known CVEs
 *   365+ days:    Critical — device should not be used for sensitive
 *                            work in a hostile environment
 */
object PatchLevelStaleness {

    const val id = "patch-level-staleness"

    private val ISO = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT)

    /** Result of one evaluation. Null when the device's patch string
     *  is unparseable or unavailable. */
    fun evaluate(): Alert? {
        val raw = Build.VERSION.SECURITY_PATCH ?: return null
        val patchDate = try { ISO.parse(raw) } catch (_: Throwable) { null } ?: return null
        val now = System.currentTimeMillis()
        val ageDays = TimeUnit.MILLISECONDS.toDays(now - patchDate.time).coerceAtLeast(0)

        val severity: Severity = when {
            ageDays <  60  -> return null
            ageDays < 180  -> Severity.Medium
            ageDays < 365  -> Severity.High
            else           -> Severity.Critical
        }
        val ev = JSONObject().apply {
            put("patch_level", raw)
            put("age_days", ageDays)
            put("device", Build.MODEL)
            put("android_release", Build.VERSION.RELEASE)
        }
        return Alert(
            tsMs = now,
            heuristic = Heuristic.Permission_Diff, // re-use tag pending Heuristic.PatchStale enum entry
            severity = severity,
            summary = "Patch level ${ageDays}d old (${raw}) on ${Build.MODEL}",
            evidenceJson = ev.toString(),
            geohash6 = null,
        )
    }
}

