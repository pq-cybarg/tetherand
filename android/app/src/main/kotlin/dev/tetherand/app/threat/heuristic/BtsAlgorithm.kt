package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.CellObservation
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * AIMSICD-derived BTS scoring adapted for non-root use on MediaTek.
 * Without /dev/diag access we trade certainty for coverage:
 *
 *   • +30  cell unseen in this geohash6 baseline (most informative)
 *   • +20  anomalously high signal (RSRP > -65 dBm)
 *   • +20  zero neighboring cells reported
 *
 * Total score → Severity bucket; below 15 → no alert.
 *
 * Original AIMSICD source:
 *   app/src/main/java/com/SecUpwN/AIMSICD/utils/BTSAlgorithm.java
 * License: GPLv3 (this module inherits).
 */
class BtsAlgorithm(private val baseline: BaselineStore) {
    suspend fun evaluate(geohash6: String, obs: CellObservation): Alert? {
        var score = 0
        val reasons = mutableListOf<String>()

        if (baseline.isNew(geohash6, obs)) {
            score += 30
            reasons += "unseen in this location ($geohash6)"
        }
        val rsrp = obs.signalDbm
        if (rsrp != null && rsrp > -65) {
            score += 20
            reasons += "anomalously high signal $rsrp dBm"
        }
        if (obs.neighborCount == 0) {
            score += 20
            reasons += "no neighbor cells reported"
        }

        if (score < 15) return null
        val severity = when {
            score >= 60 -> Severity.Critical
            score >= 30 -> Severity.High
            else        -> Severity.Medium
        }

        val evidence = JSONObject().apply {
            put("score", score)
            put("reasons", reasons.joinToString("; "))
            put("rat", obs.rat)
            put("mccMnc", obs.mccMnc)
            put("lac", obs.lac)
            put("cid", obs.cid)
            put("rsrp", rsrp ?: JSONObject.NULL)
            put("neighbors", obs.neighborCount)
        }

        return Alert(
            tsMs = System.currentTimeMillis(),
            heuristic = Heuristic.Bts_Algorithm,
            severity = severity,
            summary = "Suspicious tower: ${reasons.first()}",
            evidenceJson = evidence.toString(),
            geohash6 = geohash6,
        )
    }
}
