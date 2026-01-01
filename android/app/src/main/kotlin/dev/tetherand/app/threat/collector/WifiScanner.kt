package dev.tetherand.app.threat.collector

import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager

data class WifiAp(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val frequencyMhz: Int,
    val tsMs: Long = System.currentTimeMillis(),
)

class WifiScanner(private val ctx: Context) {
    fun snapshot(): List<WifiAp> {
        // Emulator path: stock WifiManager.scanResults is empty/synthetic,
        // and EvilTwinWifi has nothing to compare against. Inject a
        // baseline + intentional evil-twin pair so the heuristic
        // produces alerts during emulator runs.
        if (HardwareMocks.shouldMockWifi()) {
            return HardwareMocks.syntheticWifi()
        }
        val wifi = ctx.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return try {
            wifi.scanResults.map { it.toAp() }
        } catch (_: SecurityException) { emptyList() }
    }
    private fun ScanResult.toAp(): WifiAp = WifiAp(
        ssid = SSID.orEmpty(),
        bssid = BSSID.orEmpty(),
        rssi = level,
        frequencyMhz = frequency,
    )
}
