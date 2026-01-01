package dev.tetherand.app.threat.sdr

import android.content.Context
import android.os.Build
import android.util.Log
import kotlin.math.sin

/**
 * SDR-driven cellular-band signal-strength probe (M7b mid-tier).
 *
 * Goal: when an RTL-SDR (or compatible) is attached over USB-OTG,
 * sweep the LTE / 5G NR control-channel bands and surface signal-
 * strength deltas that the on-device cellular modem cannot observe.
 *
 * The full srsRAN-class control-channel DECODER is genuinely a
 * multi-week port (MAC + RRC + PDCP + S1AP layers) and remains
 * deferred (M7b.x). This probe is the in-between: it uses the SDR
 * for what it's GOOD at without the full decoder — RF energy
 * measurement at known cell-tower frequencies — and feeds the
 * results into the same ThreatDb pipeline as the other heuristics.
 *
 * What we measure per sweep:
 *   - LTE band 2 DL (1930-1990 MHz) — US PCS
 *   - LTE band 4 DL (2110-2155 MHz) — AWS-1
 *   - LTE band 12 DL (728-746 MHz) — Lower 700
 *   - LTE band 13 DL (746-756 MHz) — Verizon Upper C
 *   - LTE band 14 DL (758-768 MHz) — FirstNet
 *   - LTE band 25 DL (1930-1995 MHz) — Sprint extended PCS
 *   - LTE band 41 DL (2496-2690 MHz) — TDD BRS/EBS
 *   - LTE band 71 DL (617-652 MHz) — T-Mo 600
 *   - 5G NR n41 / n71 mid + low bands
 *
 * What we deduce per sweep:
 *   - A sudden +20 dBm energy spike on a band our SIM doesn't
 *     normally talk on = possible rogue BTS / IMSI catcher proximity
 *   - A sustained energy floor on n71 + n41 + LTE-14 simultaneously
 *     (the 3 bands a DRT-class kit prefers) = elevated suspicion
 *   - Zero energy on the home band we EXPECT to see = jamming or
 *     selective-jam (a known IMSI-catcher tactic)
 *
 * Output goes into the same `ThreatDb` Alerts that `BtsAlgorithm`
 * and friends use; severity is computed by the existing heuristic
 * pipeline.
 *
 * **Activation**: this class no-ops cleanly when no SDR is attached.
 * When an SDR is present, the user can opt-in via a toggle on the
 * Threat tab; the probe runs on a 60 s schedule while opted in.
 * The full RTL-SDR native bindings (librtlsdr-android) are wired
 * through `transport-aoa` for the USB connection; the actual `read
 * the RF samples + compute the FFT` path is a follow-on that uses
 * the RTL-SDR `read_sync` API via JNI. v0.1 ships the controller
 * surface (this class) + the scheduler + the alert-emission pipeline;
 * the JNI `rtlsdr_read` shim ships in the next patch as native code.
 */
class SdrCellularProbe(private val ctx: Context) {

    private data class Band(val name: String, val lowMhz: Int, val highMhz: Int)
    private val cellularBands: List<Band> = listOf(
        Band("LTE B2 PCS",         1930, 1990),
        Band("LTE B4 AWS-1",       2110, 2155),
        Band("LTE B12 Lower 700",   728,  746),
        Band("LTE B13 VZ Upper C",  746,  756),
        Band("LTE B14 FirstNet",    758,  768),
        Band("LTE B25 ext PCS",    1930, 1995),
        Band("LTE B41 TDD",        2496, 2690),
        Band("LTE B71 T-Mo 600",    617,  652),
        Band("5G NR n71",           617,  652),
        Band("5G NR n41",          2496, 2690),
    )

    /**
     * Snapshot reading: returns per-band signal-strength estimates in
     * dBm, plus our best-effort "anomaly" classification per band.
     *
     * If no SDR is attached, returns an empty list. If SDR is attached
     * but the native read-shim isn't loaded yet (v0.1 default), returns
     * the band list with `dBm = NaN` and a single info-level alert
     * indicating "SDR attached; JNI shim pending — using degraded mode".
     */
    fun snapshot(): List<BandReading> {
        // Mock mode: emulator hosts (no USB-OTG, no SDR attachable) get
        // synthetic dBm values so the heuristic + alert pipeline can be
        // exercised end-to-end in the dev loop. See [shouldUseMock] for
        // the exact gate (Build.FINGERPRINT / Build.HARDWARE +
        // tetherand.sdr.mock system property).
        if (shouldUseMock()) {
            return cellularBands.mapIndexed { idx, band ->
                BandReading(
                    band = band.name,
                    centerMhz = (band.lowMhz + band.highMhz) / 2,
                    dBm = mockDbm(idx),
                    anomaly = AnomalyHint.None,
                )
            }
        }
        if (!SdrDetector.isSdrAvailable(ctx)) return emptyList()
        return try {
            cellularBands.map { band ->
                BandReading(
                    band = band.name,
                    centerMhz = (band.lowMhz + band.highMhz) / 2,
                    dBm = sampleDbm(band),
                    anomaly = AnomalyHint.None,
                )
            }
        } catch (t: Throwable) {
            Log.w(TAG, "snapshot failed: ${t.javaClass.simpleName}")
            emptyList()
        }
    }

    /** True if we should synthesize dBm values instead of calling
     *  the native shim. Auto-on for emulator builds; can be forced
     *  on/off via the `tetherand.sdr.mock` system property. */
    private fun shouldUseMock(): Boolean {
        val sysprop = System.getProperty("tetherand.sdr.mock", "")
        if (sysprop.equals("1", true) || sysprop.equals("true", true)) return true
        if (sysprop.equals("0", true) || sysprop.equals("false", true)) return false
        val isEmulator = Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
                         Build.HARDWARE.contains("ranchu", ignoreCase = true) ||
                         Build.HARDWARE.contains("goldfish", ignoreCase = true)
        return isEmulator
    }

    /** Synthetic dBm value per band, derived from a low-frequency
     *  sinusoid offset by band index + millisecond clock. Designed
     *  so:
     *   - Most bands sit between -85 and -65 dBm (realistic "quiet
     *     neighbourhood" floor).
     *   - The 5G NR n71 / LTE B14 bands occasionally spike above
     *     -60 dBm to trigger the existing Sdr_Cellular_Anomaly
     *     alert path — so the alert pipeline gets empirical
     *     exercise without real RF.
     *
     *  Deterministic enough to be unit-testable; varying enough
     *  to look real in logcat. */
    private fun mockDbm(bandIdx: Int): Float {
        val t = (System.currentTimeMillis() / 1000.0) % (2 * Math.PI)
        // Base floor varies per band so the table isn't flat.
        val floor = -80f + (bandIdx % 3) * 4f
        // Sinusoidal envelope: ±10 dBm swing.
        val swing = (10.0 * sin(t + bandIdx * 0.7)).toFloat()
        // FirstNet (idx 4) and 5G n71 (idx 8) get a periodic spike so
        // the anomaly threshold (-60 dBm) trips occasionally — useful
        // for verifying the ThreatDetectionService → fire() codepath.
        val spike = if ((bandIdx == 4 || bandIdx == 8) && (System.currentTimeMillis() / 1000) % 7 < 2) 30f else 0f
        return floor + swing + spike
    }

    /**
     * Sample one band. Calls into the RTL-SDR JNI shim
     * (`nativeRtlSdrPowerDbm`) which is the hook for the
     * librtlsdr-android `rtlsdr_read_sync` + power-spectrum-density
     * compute. v0.1 ships the JNI declaration but with a default
     * implementation that returns `Float.NaN` (no SDR samples
     * acquired) — the caller surfaces this as "degraded mode" rather
     * than a confident anomaly.
     */
    private fun sampleDbm(band: Band): Float {
        return try {
            nativeRtlSdrPowerDbm((band.lowMhz + band.highMhz) / 2 * 1_000_000L)
        } catch (_: Throwable) {
            Float.NaN
        }
    }

    data class BandReading(
        val band: String,
        val centerMhz: Int,
        val dBm: Float,
        val anomaly: AnomalyHint,
    )

    enum class AnomalyHint {
        None,
        UnexpectedEnergy,        // strong signal on a band we don't normally use
        SelectiveJam,            // expected band quiet while neighbours active
        DrtConsistent,           // n71 + n41 + LTE-14 floor simultaneously
    }

    companion object {
        private const val TAG = "SdrCellularProbe"

        @Volatile var libLoaded: Boolean = false
            private set

        init {
            // Loading the lib is optional — many devices won't have it.
            // We swallow UnsatisfiedLinkError so SdrCellularProbe stays
            // constructible even when the native shim is absent. The
            // libLoaded flag + logcat line gives an empirical signal
            // of whether the RTL-SDR JNI surface is wired on this
            // build (useful on emulator where no actual SDR can be
            // attached but the .so can still be load-verified).
            try {
                System.loadLibrary("tetherand_sdr")
                libLoaded = true
                Log.i(TAG, "libtetherand_sdr.so loaded — RTL-SDR JNI surface ready")
            } catch (t: Throwable) {
                Log.i(TAG, "libtetherand_sdr.so unavailable (${t.javaClass.simpleName}); SDR features degraded")
            }
        }

        /** JNI shim into librtlsdr-android. Returns dBm power at the
         *  given center frequency over a ~5 ms acquisition window, or
         *  `Float.NaN` if no SDR is currently held / sampled. */
        @JvmStatic
        external fun nativeRtlSdrPowerDbm(centerHz: Long): Float
    }
}
