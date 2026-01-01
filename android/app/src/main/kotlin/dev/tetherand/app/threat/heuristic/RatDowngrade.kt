package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.CellObservation
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * SnoopSnitch-derived: alert when the serving cell's RAT drops from
 * LTE/NR to GSM/UMTS in a location where we previously observed only
 * LTE/NR. Stingrays force this downgrade to capture IMSI in cleartext.
 *
 * Trigger requires BOTH:
 *   • no modern (LTE/NR) cell currently visible
 *   • this geohash6 has LTE/NR history in the baseline
 */
class RatDowngrade(private val baseline: BaselineStore) {

    suspend fun evaluate(geohash6: String, fresh: List<CellObservation>): Alert? {
        val rats = fresh.map { it.rat }.toSet()
        if (rats.intersect(MODERN).isNotEmpty()) return null
        if (rats.intersect(LEGACY).isEmpty()) return null
        if (!baseline.hasModernRatHistory(geohash6)) return null

        val legacyCell = fresh.first { it.rat in LEGACY }
        val ev = JSONObject().apply {
            put("rats", rats.joinToString(","))
            put("legacyCid", legacyCell.cid)
            put("legacyMccMnc", legacyCell.mccMnc)
            put("geohash6", geohash6)
        }
        return Alert(
            tsMs = System.currentTimeMillis(),
            heuristic = Heuristic.Rat_Downgrade,
            severity = Severity.High,
            summary = "RAT downgrade: only ${rats.first()} visible in an LTE/NR-baseline area",
            evidenceJson = ev.toString(),
            geohash6 = geohash6,
        )
    }

    companion object {
        private val MODERN = setOf("LTE", "NR")
        private val LEGACY = setOf("GSM", "UMTS")
    }
}
