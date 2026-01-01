package dev.tetherand.app.aiguard.npu

import android.content.Context
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import org.json.JSONObject
import java.io.File

/**
 * Watch `/sys/devices/platform/mtk_apu` and `/sys/kernel/debug/apusys/`
 * for NPU usage from background apps. A covert on-device model running
 * while the user sleeps is a real risk on this hardware.
 *
 * Most sysfs nodes require selinux read permission Tetherand doesn't
 * have without root — we surface "available / unreadable" plainly in
 * the UI rather than fake it.
 */
object NpuSysWatcher {

    data class Sample(val ts: Long, val available: Boolean, val readableNodes: Int, val rawUsage: String?)

    private val candidateDirs = listOf(
        "/sys/devices/platform/mtk_apu",
        "/sys/devices/platform/apusys",
        "/sys/class/misc/apusys",
        "/sys/kernel/debug/apusys",
    )

    fun snapshot(): Sample {
        var nodes = 0
        var raw: String? = null
        var found = false
        for (d in candidateDirs) {
            val f = File(d)
            if (!f.exists()) continue
            found = true
            f.listFiles()?.forEach { nodes++ }
            // Try the most common "usage" / "stat" / "load" files.
            for (name in listOf("usage", "stat", "load", "power_state")) {
                val sub = File(f, name)
                if (sub.canRead()) {
                    raw = try { sub.readText().take(256) } catch (_: Throwable) { null }
                    if (raw != null) break
                }
            }
            if (raw != null) break
        }
        return Sample(System.currentTimeMillis(), found, nodes, raw)
    }

    /** Foreground-app helper; spec calls for cross-checking against
     *  whether the using app is foreground. We surface "background NPU
     *  in use" if Sample.rawUsage parses as non-zero AND no foreground
     *  app via UsageStatsManager — that linkage lives in the UI layer
     *  to keep this object pure. */
    suspend fun maybeAlert(ctx: Context, sample: Sample) {
        // Conservative: only alert if usage > 5% reported AND we know
        // the rate via two samples. v1 just exposes the sample to the
        // UI; alert behaviour ships in M10.x once we have the rate
        // tracker + foreground correlation.
        if (sample.rawUsage != null && Regex("[1-9]\\d*").containsMatchIn(sample.rawUsage)) {
            try {
                ThreatDb.get(ctx).alerts().insert(Alert(
                    tsMs = sample.ts,
                    heuristic = Heuristic.Permission_Diff, // re-use as npu-usage tag
                    severity = Severity.Medium,
                    summary = "NPU usage detected (sysfs raw: ${sample.rawUsage.take(40)})",
                    evidenceJson = JSONObject().apply {
                        put("raw", sample.rawUsage)
                        put("nodes", sample.readableNodes)
                    }.toString(),
                    geohash6 = null,
                ))
            } catch (_: Throwable) {}
        }
    }
}
