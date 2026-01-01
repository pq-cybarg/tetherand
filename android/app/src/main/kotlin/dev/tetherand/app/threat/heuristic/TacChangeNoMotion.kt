package dev.tetherand.app.threat.heuristic

import android.location.Location
import dev.tetherand.app.threat.collector.CellObservation
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * Crocodile Hunter signal: LTE/NR TAC changes but the phone hasn't
 * moved. Stingrays often broadcast a new TAC to force re-attach (which
 * leaks the IMSI). Genuine TAC changes correlate with geographic motion.
 *
 * Window: track the last seen TAC + location. Trigger when TAC changes
 * AND geographic motion < 200m since the previous observation.
 */
class TacChangeNoMotion {
    private var lastTac: Int? = null
    private var lastLocation: Location? = null

    fun evaluate(obs: CellObservation, currentLoc: Location?): Alert? {
        val tac = obs.tac ?: return null
        val prevTac = lastTac
        val prevLoc = lastLocation
        lastTac = tac
        lastLocation = currentLoc
        if (prevTac == null || prevTac == tac) return null
        if (currentLoc == null || prevLoc == null) return null
        val meters = prevLoc.distanceTo(currentLoc)
        if (meters > 200f) return null  // genuine motion

        val ev = JSONObject().apply {
            put("oldTac", prevTac)
            put("newTac", tac)
            put("motionMeters", meters.toInt())
        }
        return Alert(
            tsMs = System.currentTimeMillis(),
            heuristic = Heuristic.Tac_Change_No_Motion,
            severity = Severity.High,
            summary = "TAC changed $prevTac → $tac without motion (${meters.toInt()}m)",
            evidenceJson = ev.toString(),
            geohash6 = null,
        )
    }
}
