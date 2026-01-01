package dev.tetherand.app.threat.collector

import android.os.Build
import kotlin.math.sin
import kotlin.random.Random

/**
 * Synthetic-hardware data sources for the development emulator.
 *
 * Android emulators don't have cellular modems, real Wi-Fi
 * scan results, or BLE radios. Without mocks the threat-detection
 * pipeline (BtsAlgorithm, RatDowngrade, EvilTwinWifi, etc.) gets
 * an empty input stream and never produces alerts — which means
 * regressions in those heuristics ship undetected.
 *
 * `HardwareMocks` injects deterministic-yet-varying sample data
 * into [CellInfoSource] and [WifiScanner] when we're running on
 * an emulator or when the per-feature `tetherand.<feature>.mock`
 * system property is set. The samples include the occasional
 * anomaly (RAT downgrade, evil-twin pair, etc.) so the alert
 * pipeline gets empirical exercise on the dev loop.
 *
 * See feedback_hardware_mocks.md for the policy this implements.
 */
object HardwareMocks {

    /** True if we should inject synthetic cellular observations. */
    fun shouldMockCellular(): Boolean = mockGate("tetherand.cell.mock")

    /** True if we should inject synthetic Wi-Fi scan results. */
    fun shouldMockWifi(): Boolean = mockGate("tetherand.wifi.mock")

    private fun mockGate(prop: String): Boolean {
        val sysprop = System.getProperty(prop, "")
        if (sysprop.equals("1", true) || sysprop.equals("true", true)) return true
        if (sysprop.equals("0", true) || sysprop.equals("false", true)) return false
        return Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
               Build.HARDWARE.contains("ranchu", ignoreCase = true) ||
               Build.HARDWARE.contains("goldfish", ignoreCase = true)
    }

    /**
     * Synthetic cell environment. Returns a small set of plausible
     * LTE/NR observations with slowly-changing CIDs and TACs. Once
     * every ~5 minutes the set briefly downgrades to a single GSM
     * cell (no neighbours, weak signal) — a pattern the
     * RatDowngrade heuristic flags as suspicious. That gives the
     * BTS + RAT heuristics empirical input on emulator.
     */
    fun syntheticCells(): List<CellObservation> {
        val t = System.currentTimeMillis() / 1000
        // Every 5 min cycle: minutes 0-4 → LTE+NR healthy; minute 4-5 → GSM downgrade.
        val phase = (t / 60) % 5
        if (phase == 4L) {
            return listOf(
                CellObservation(
                    rat = "GSM",
                    mccMnc = "310260",     // T-Mobile US
                    lac = 4321,
                    cid = 9001,
                    signalDbm = -103,
                    neighborCount = 0,
                ),
            )
        }
        // Stable baseline cell so ReattachStorm (>4 distinct CIDs in 60s)
        // and TacChangeNoMotion stay quiet. Only the periodic GSM-only
        // window is meant to fire any heuristic.
        val baseLte = CellObservation(
            rat = "LTE",
            mccMnc = "310260",
            lac = 17,
            tac = 17,
            cid = 0x1A2B3C,
            pci = 121,
            earfcn = 1975,                  // band 2 mid-channel; in T-Mobile (310260)
                                            // allowed range so EarfcnAllocation stays quiet
            signalDbm = -82,
            neighborCount = 3,
        )
        val baseNr = CellObservation(
            rat = "NR",
            mccMnc = "310260",
            lac = 17,
            tac = 17,
            cid = 0xC0DE5,
            pci = 73,
            earfcn = 643000,                // n41 DL
            signalDbm = -78,
            neighborCount = 2,
        )
        return listOf(baseLte, baseNr)
    }

    /**
     * Synthetic Wi-Fi APs. Returns 4 always-present APs (the
     * "home / coffee shop / neighbour" baseline) plus a fifth
     * AP that flips its BSSID every ~3 minutes while keeping
     * the same SSID — the canonical evil-twin pattern that
     * [EvilTwinWifi] is supposed to flag.
     */
    fun syntheticWifi(): List<WifiAp> {
        val t = System.currentTimeMillis() / 1000
        val rotation = (t / 180) % 2          // flips every 3 minutes
        val evilBssid = if (rotation == 0L) "AA:BB:CC:00:00:01" else "AA:BB:CC:00:00:02"
        return listOf(
            WifiAp(ssid = "Tetherand-Home",    bssid = "10:20:30:40:50:60", rssi = -42, frequencyMhz = 2437),
            WifiAp(ssid = "Coffee-WiFi",       bssid = "11:22:33:44:55:66", rssi = -65, frequencyMhz = 5180),
            WifiAp(ssid = "Verizon-Lobby",     bssid = "77:88:99:AA:BB:CC", rssi = -71, frequencyMhz = 2462),
            WifiAp(ssid = "linksys-default",   bssid = "DE:AD:BE:EF:00:01", rssi = -85, frequencyMhz = 2412),
            WifiAp(ssid = "Tetherand-Home",    bssid = evilBssid,           rssi = -60, frequencyMhz = 2437),
        )
    }

    /** Random source seeded from the millisecond clock for the small
     *  amount of jitter the synthetic generators need. Deterministic
     *  enough that consecutive samples from a single run aren't
     *  identical-noise but varied enough to look real in logcat. */
    private val rng = Random(System.currentTimeMillis())
    @Suppress("unused")
    private fun jitter(spread: Int): Int = rng.nextInt(-spread, spread + 1)
}
