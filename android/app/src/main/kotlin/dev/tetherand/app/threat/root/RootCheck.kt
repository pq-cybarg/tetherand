package dev.tetherand.app.threat.root

import java.io.File

/**
 * Capability detection for root-tier modem readers.
 *
 * Three signals; we only claim root if at least two agree:
 *   1. su binary present at a stock location
 *   2. system partition writable (root-only on stock Android)
 *   3. Runtime.exec("su -c id") returns uid=0
 *
 * On un-rooted devices, every M7c reader returns a clean "Dormant"
 * state instead of throwing — the UI surfaces this honestly.
 */
object RootCheck {

    private val SU_PATHS = listOf(
        "/system/xbin/su", "/system/bin/su", "/sbin/su",
        "/su/bin/su",       // Magisk
        "/system/app/Superuser.apk",
    )

    fun isRooted(): Boolean {
        var votes = 0
        if (SU_PATHS.any { File(it).exists() }) votes++
        if (File("/system").canWrite()) votes++
        if (canRunSu()) votes++
        return votes >= 2
    }

    private fun canRunSu(): Boolean = try {
        val p = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readLine() ?: ""
        p.waitFor()
        "uid=0" in out
    } catch (_: Throwable) { false }
}
