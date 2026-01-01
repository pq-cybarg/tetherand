package dev.tetherand.app.hardened.ultrasonic

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import androidx.core.content.ContextCompat
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.ln
import kotlin.math.sin
import kotlin.math.PI

/**
 * Listens for ultrasonic side-channel beacons in the 18&ndash;22 kHz
 * band &mdash; the range used by cross-device tracking systems
 * (SilverPush, Signal360, Lisnr, the AT&amp;T uBeacon family) to
 * correlate a phone's physical presence with a TV ad, conference
 * badge, in-store kiosk, or another phone running the same SDK.
 *
 * Detection signal: sustained energy concentrated in the 18&ndash;22 kHz
 * band beyond a 12 dB threshold above the noise floor over a 1.5 s
 * window. Single transient peaks are ignored (they are dominated by
 * keyboard taps, microwaves, fluorescent lighting); only sustained
 * narrow-band emissions in the ultrasonic range fire an alert.
 *
 * Sampling at 44.1 kHz gives us a Nyquist of 22.05 kHz, which covers
 * the upper end of every documented ultrasonic beacon protocol. The
 * FFT runs on 1024-sample windows (~23 ms each) so a 1.5 s decision
 * window is ~65 windows.
 *
 * Permission: requires RECORD_AUDIO. If absent, the listener fires
 * one informational alert at start and shuts down cleanly.
 */
class UltrasonicListener(private val ctx: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    private val sampleRate = 44_100
    private val fftSize = 1024
    /** 18 kHz bin index for 44.1 kHz sample rate over 1024-bin FFT. */
    private val ultraBinLo = (18_000.0 * fftSize / sampleRate).toInt()
    /** 22 kHz bin index (capped at Nyquist). */
    private val ultraBinHi = ((22_000.0 * fftSize / sampleRate).toInt()).coerceAtMost(fftSize / 2 - 1)
    /** Audible reference band (1-4 kHz) — we measure ultrasonic energy
     *  against this so a generally loud room doesn't trigger us. */
    private val refBinLo = (1_000.0 * fftSize / sampleRate).toInt()
    private val refBinHi = (4_000.0 * fftSize / sampleRate).toInt()

    /** dB above reference-band energy to call it "sustained ultrasonic". */
    private val thresholdDb = 12.0

    /** How many consecutive windows must clear the threshold before
     *  we fire an alert. ~65 windows = 1.5 s. */
    private val sustainedWindows = 65

    fun start() {
        if (job?.isActive == true) return
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            fireOnce(Severity.Medium, "Ultrasonic listener disabled — RECORD_AUDIO permission missing.",
                     "{\"permission\":\"RECORD_AUDIO\"}")
            return
        }
        job = scope.launch { runLoop() }
    }

    fun stop() {
        job?.cancel(); job = null
        scope.cancel()
    }

    private suspend fun runLoop() {
        val bufBytes = AudioRecord.getMinBufferSize(
            sampleRate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT
        ).coerceAtLeast(fftSize * 4)

        val recorder = try {
            AudioRecord(MediaRecorder.AudioSource.MIC, sampleRate,
                        AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, bufBytes)
        } catch (t: Throwable) {
            fireOnce(Severity.Medium, "Ultrasonic listener could not open the mic: ${t.message}",
                     "{}")
            return
        }
        try {
            recorder.startRecording()
        } catch (t: Throwable) {
            fireOnce(Severity.Medium, "Ultrasonic listener startRecording failed: ${t.message}", "{}")
            recorder.release(); return
        }

        val samples = ShortArray(fftSize)
        var sustained = 0
        var peakDb = 0.0
        var peakBin = 0

        while (scope.isActive) {
            val n = try { recorder.read(samples, 0, fftSize) } catch (_: Throwable) { -1 }
            if (n <= 0) break

            // Real-input FFT. We don't pull in a heavy FFT lib for this —
            // 1024 samples is small enough that a direct DFT over only
            // the bins we care about (the ultrasonic + reference bands)
            // is cheap. Total work is ~(ultraHi - ultraLo) * fftSize
            // multiply-adds per window — well under a millisecond.
            val ultra = bandEnergy(samples, n, ultraBinLo, ultraBinHi)
            val refer = bandEnergy(samples, n, refBinLo, refBinHi)
            if (refer < 1.0) continue   // total silence — skip
            val (ultraDom, dominantBin) = peakInBand(samples, n, ultraBinLo, ultraBinHi)
            val db = 10.0 * ln(ultra / refer) / ln(10.0)

            if (db >= thresholdDb && ultraDom >= refer * 0.5) {
                sustained++
                if (db > peakDb) { peakDb = db; peakBin = dominantBin }
                if (sustained >= sustainedWindows) {
                    val freqHz = (peakBin.toDouble() * sampleRate / fftSize).toInt()
                    val ev = JSONObject().apply {
                        put("freq_hz_peak", freqHz)
                        put("ultrasonic_vs_audible_db", peakDb)
                        put("sustained_windows", sustained)
                    }
                    safeInsert(Alert(
                        tsMs = System.currentTimeMillis(),
                        heuristic = Heuristic.Permission_Diff,
                        severity = Severity.High,
                        summary = "Ultrasonic beacon detected at ${freqHz} Hz (+${"%.1f".format(peakDb)} dB sustained)",
                        evidenceJson = ev.toString(),
                        geohash6 = null,
                    ))
                    sustained = 0
                    peakDb = 0.0
                    peakBin = 0
                }
            } else {
                // Cool the counter slowly so a brief drop-out doesn't reset.
                if (sustained > 0) sustained -= 1
            }
        }
        try { recorder.stop() } catch (_: Throwable) {}
        recorder.release()
    }

    /** Sum of squared magnitudes across the named FFT bins. */
    private fun bandEnergy(samples: ShortArray, n: Int, lo: Int, hi: Int): Double {
        var energy = 0.0
        for (k in lo..hi) {
            val (re, im) = dftBin(samples, n, k)
            energy += re * re + im * im
        }
        return energy
    }

    private fun peakInBand(samples: ShortArray, n: Int, lo: Int, hi: Int): Pair<Double, Int> {
        var bestE = 0.0
        var bestK = lo
        for (k in lo..hi) {
            val (re, im) = dftBin(samples, n, k)
            val e = re * re + im * im
            if (e > bestE) { bestE = e; bestK = k }
        }
        return bestE to bestK
    }

    /** Naive single-bin DFT. Adequate for the small bin counts we
     *  evaluate per window; pulling in a full FFT library for this
     *  one detector isn't worth the dep weight. */
    private fun dftBin(samples: ShortArray, n: Int, k: Int): Pair<Double, Double> {
        var re = 0.0
        var im = 0.0
        val coef = -2.0 * PI * k / fftSize
        for (i in 0 until n) {
            val s = samples[i].toDouble()
            re += s * cos(coef * i)
            im += s * sin(coef * i)
        }
        return re to im
    }

    private suspend fun safeInsert(a: Alert) {
        try { ThreatDb.get(ctx).alerts().insert(a) } catch (_: Throwable) {}
    }

    private fun fireOnce(severity: Severity, summary: String, evidence: String) {
        scope.launch {
            safeInsert(Alert(
                tsMs = System.currentTimeMillis(),
                heuristic = Heuristic.Permission_Diff,
                severity = severity,
                summary = summary,
                evidenceJson = evidence,
                geohash6 = null,
            ))
        }
    }

    /** Convenience so the audible-band reference can be sanity-checked. */
    @Suppress("unused")
    fun audibleBinRange() = refBinLo..refBinHi
    @Suppress("unused")
    fun ultrasonicBinRange() = ultraBinLo..ultraBinHi
}
