package dev.tetherand.app.crypto

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.TrafficStats
import android.os.BatteryManager
import android.os.Build
import android.os.Process
import android.os.SystemClock
import org.bouncycastle.jcajce.provider.digest.SHA3
import java.io.File

/**
 * "Current device activity" entropy source for SeekerRng.
 *
 * Returns `SHA3-256(<concatenation of a dozen jittery system signals>)`.
 * Each signal is individually low-entropy and predictable to a
 * privileged observer — but in aggregate, faking all of them
 * simultaneously and consistently across consecutive calls is
 * substantially harder than faking any one. An attacker who has
 * compromised our process can read these values, but they cannot
 * easily make them DETERMINISTIC (i.e. always-the-same across two
 * back-to-back calls) without us noticing — battery temperature
 * drifts, RX/TX bytes climb monotonically, /proc/uptime advances,
 * scheduler runtime accumulates.
 *
 * SHAKE-256 in SeekerRng absorbs the 32-byte SHA3-256 output among
 * its other sources; under the random-oracle assumption the bias
 * resistance argument applies — this source contributes positively
 * to the output as long as SOMETHING in the activity vector is
 * unpredictable, which is essentially always true on a live device.
 *
 * Cost: ~50 µs per call (a dozen stat() syscalls + one SHA3-256
 * over a few hundred bytes). Cheap enough to absorb on every
 * `nextBytes()` invocation.
 *
 * Signals captured:
 *   - Battery level / voltage / temperature (BatteryManager)
 *   - Network RX / TX byte counts (TrafficStats)
 *   - Per-process RX / TX byte counts (TrafficStats myUid)
 *   - Process CPU times (Process.getElapsedCpuTime + threadCpuTime)
 *   - /proc/uptime + /proc/loadavg
 *   - /proc/self/stat resident-set-size, num-threads, etc.
 *   - Runtime freeMemory / totalMemory
 *   - SystemClock.elapsedRealtimeNanos + uptimeMillis
 *
 * No permissions needed — all signals are accessible to any
 * userspace process at zero privilege cost.
 */
object ActivityFingerprint {

    /** 32-byte SHA3-256 fingerprint of the current device activity. */
    fun snapshot(ctx: Context): ByteArray {
        val sha3 = SHA3.Digest256()

        // BatteryManager — level / voltage / temperature. Each drifts
        // on its own schedule.
        try {
            val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
            val intent = ctx.applicationContext.registerReceiver(null, filter)
            if (intent != null) {
                sha3.update(intToBytes(intent.getIntExtra(BatteryManager.EXTRA_LEVEL, 0)))
                sha3.update(intToBytes(intent.getIntExtra(BatteryManager.EXTRA_SCALE, 0)))
                sha3.update(intToBytes(intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0)))
                sha3.update(intToBytes(intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0)))
                sha3.update(intToBytes(intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)))
                sha3.update(intToBytes(intent.getIntExtra(BatteryManager.EXTRA_STATUS, 0)))
            }
        } catch (_: Throwable) {}

        // TrafficStats — total + per-uid RX/TX byte counts. Monotonic;
        // adversary cannot rewind without the user noticing the
        // network meter.
        try {
            sha3.update(longToBytes(TrafficStats.getTotalRxBytes()))
            sha3.update(longToBytes(TrafficStats.getTotalTxBytes()))
            sha3.update(longToBytes(TrafficStats.getUidRxBytes(Process.myUid())))
            sha3.update(longToBytes(TrafficStats.getUidTxBytes(Process.myUid())))
        } catch (_: Throwable) {}

        // Process / thread CPU clocks. Different schedulers, so two
        // back-to-back snapshots will diverge by the cost of the
        // intervening SHA3 update.
        try {
            sha3.update(longToBytes(Process.getElapsedCpuTime()))
            sha3.update(longToBytes(android.os.Debug.threadCpuTimeNanos()))
        } catch (_: Throwable) {}

        // /proc/uptime — system uptime + idle-time accumulator.
        try {
            val s = File("/proc/uptime").readText().trim()
            sha3.update(s.toByteArray(Charsets.UTF_8))
        } catch (_: Throwable) {}

        // /proc/loadavg — three load averages + running/total processes.
        try {
            val s = File("/proc/loadavg").readText().trim()
            sha3.update(s.toByteArray(Charsets.UTF_8))
        } catch (_: Throwable) {}

        // /proc/self/stat — resident set size, num threads, vsize, etc.
        try {
            val s = File("/proc/self/stat").readText().trim()
            sha3.update(s.toByteArray(Charsets.UTF_8))
        } catch (_: Throwable) {}

        // JVM heap — free / total / max bytes.
        try {
            val r = Runtime.getRuntime()
            sha3.update(longToBytes(r.freeMemory()))
            sha3.update(longToBytes(r.totalMemory()))
            sha3.update(longToBytes(r.maxMemory()))
        } catch (_: Throwable) {}

        // Monotonic clocks. elapsedRealtimeNanos includes deep-sleep
        // time; uptimeMillis does not. The two together leak
        // sleep-vs-active scheduler patterns.
        try {
            sha3.update(longToBytes(SystemClock.elapsedRealtimeNanos()))
            sha3.update(longToBytes(SystemClock.uptimeMillis()))
            sha3.update(longToBytes(System.nanoTime()))
        } catch (_: Throwable) {}

        // Build fingerprint — static (constant across snapshots) but
        // domain-separates two devices that happen to have identical
        // dynamic state.
        try {
            sha3.update(Build.FINGERPRINT.toByteArray(Charsets.UTF_8))
        } catch (_: Throwable) {}

        return sha3.digest()
    }

    private fun longToBytes(v: Long): ByteArray {
        val b = ByteArray(8)
        for (i in 0..7) b[i] = ((v shr (8 * i)) and 0xff).toByte()
        return b
    }

    private fun intToBytes(v: Int): ByteArray {
        val b = ByteArray(4)
        for (i in 0..3) b[i] = ((v shr (8 * i)) and 0xff).toByte()
        return b
    }
}
