package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.WifiAp
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * Evil twin: two access points advertise the SAME SSID but their BSSIDs
 * have different OUI (first 3 bytes of MAC). One is the real AP, the
 * other is a Pineapple-style impersonator.
 */
class EvilTwinWifi {
    fun evaluate(scan: List<WifiAp>): List<Alert> {
        val out = mutableListOf<Alert>()
        scan.groupBy { it.ssid }.forEach { (ssid, aps) ->
            if (ssid.isBlank() || aps.size < 2) return@forEach
            val ouis = aps.map { it.bssid.take(8).lowercase() }.toSet()
            if (ouis.size < 2) return@forEach  // all from same vendor → benign mesh
            val ev = JSONObject().apply {
                put("ssid", ssid)
                put("ouis", ouis.joinToString(","))
                put("count", aps.size)
            }
            out += Alert(
                tsMs = System.currentTimeMillis(),
                heuristic = Heuristic.Evil_Twin_Wifi,
                severity = Severity.High,
                summary = "Evil twin: '$ssid' broadcast by ${ouis.size} different vendors",
                evidenceJson = ev.toString(),
                geohash6 = null,
            )
        }
        return out
    }
}
