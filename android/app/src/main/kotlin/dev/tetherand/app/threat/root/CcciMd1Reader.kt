package dev.tetherand.app.threat.root

import java.io.File

/**
 * MediaTek modem diagnostic channel reader.
 *
 * On MTK chipsets the AP-to-Modem CCCI bridge exposes its IPC + log
 * channels under `/proc/ccci_md1_*`. The relevant nodes:
 *   /proc/ccci_md1_log          binary modem log stream
 *   /proc/ccci_md1_status       modem state machine (boot / online / oom)
 *   /proc/ccci_md1_ic_intr      interrupt counters per IRQ
 *   /proc/ccci_md1_smem         shared-memory descriptors
 *
 * These are root-only on stock Android. The reader returns
 * Result.Dormant on un-rooted devices instead of throwing.
 */
object CcciMd1Reader {

    sealed class Result {
        object Dormant : Result()
        data class Snapshot(val state: String, val intrCount: Map<String, Long>) : Result()
        data class Failed(val reason: String) : Result()
    }

    fun snapshot(): Result {
        if (!RootCheck.isRooted()) return Result.Dormant
        val state = readWithSu("/proc/ccci_md1_status") ?: return Result.Failed("status read failed")
        val intrs = readWithSu("/proc/ccci_md1_ic_intr") ?: ""
        val counts = mutableMapOf<String, Long>()
        for (line in intrs.lines()) {
            val parts = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (parts.size >= 2) counts[parts[0]] = parts[1].toLongOrNull() ?: 0L
        }
        return Result.Snapshot(state.trim(), counts)
    }

    private fun readWithSu(path: String): String? = try {
        val p = ProcessBuilder("su", "-c", "cat $path").redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().use { it.readText() }
        p.waitFor()
        if (out.contains("Permission denied") || out.isBlank()) null else out
    } catch (_: Throwable) {
        // Fall back to direct read in case file is world-readable on some builds.
        try { File(path).readText() } catch (_: Throwable) { null }
    }
}
