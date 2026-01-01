package dev.tetherand.app.threat.collector

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * Scans for BLE devices and flags ones matching known tracker patterns:
 * Apple AirTag (mfg 0x004C), Tile (0x008C), Samsung SmartTag (0x0075),
 * Chipolo (0x0398), Pebblebee (0x06A3). Coarse manufacturer-ID matching
 * for the MVP; richer continuity-message fingerprints can be layered on.
 */
class BluetoothScanner(private val ctx: Context) {
    private val results = mutableMapOf<String, BleSighting>()
    private var scanCallback: ScanCallback? = null

    data class BleSighting(val mac: String, val mfg: Int, val rssi: Int, val tsMs: Long)

    fun start() {
        if (!hasPermission()) return
        val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return
        val scanner = bm.adapter?.bluetoothLeScanner ?: return
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val mac = result.device.address
                val mfg = result.scanRecord?.manufacturerSpecificData?.let { sa ->
                    if (sa.size() > 0) sa.keyAt(0) else -1
                } ?: -1
                results[mac] = BleSighting(mac, mfg, result.rssi, System.currentTimeMillis())
            }
        }
        scanCallback = cb
        try {
            scanner.startScan(emptyList(), ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build(), cb)
        } catch (_: SecurityException) {}
    }

    fun stop() {
        val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return
        scanCallback?.let { try { bm.adapter?.bluetoothLeScanner?.stopScan(it) } catch (_: Throwable) {} }
        scanCallback = null
    }

    /** Flag trackers seen in the last 5 minutes. */
    fun flagged(): List<Alert> {
        val cutoff = System.currentTimeMillis() - 5L * 60 * 1000
        return results.values
            .filter { it.tsMs >= cutoff && it.mfg in TRACKER_MFGS }
            .map { sighting ->
                val ev = JSONObject().apply {
                    put("mac", sighting.mac)
                    put("mfg", "0x%04X".format(sighting.mfg))
                    put("rssi", sighting.rssi)
                }
                Alert(
                    tsMs = sighting.tsMs,
                    heuristic = Heuristic.Untrusted_Tracker_Ble,
                    severity = Severity.Medium,
                    summary = "BLE tracker nearby: ${TRACKER_MFGS[sighting.mfg]}",
                    evidenceJson = ev.toString(),
                    geohash6 = null,
                )
            }
    }

    private fun hasPermission(): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED

    companion object {
        private val TRACKER_MFGS = mapOf(
            0x004C to "Apple AirTag/Find My",
            0x008C to "Tile",
            0x0075 to "Samsung SmartTag",
            0x0398 to "Chipolo",
            0x06A3 to "Pebblebee",
        )
    }
}
