package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.CellObservation
import dev.tetherand.app.threat.model.BaselineCell
import dev.tetherand.app.threat.model.BaselineCellDao

/**
 * Wraps the BaselineCellDao with a friendlier "have I seen this cell in
 * this geohash6 before?" API. Heuristics use this to distinguish 'new
 * tower in a familiar place' (worth alerting on) from 'I'm just standing
 * somewhere I've never been' (no alert — yet, until a baseline forms).
 */
class BaselineStore(private val dao: BaselineCellDao) {

    suspend fun isNew(geohash6: String, obs: CellObservation): Boolean {
        val seen = dao.lookup(geohash6, obs.mccMnc, obs.lac, obs.cid)
        return seen == null
    }

    suspend fun observe(geohash6: String, obs: CellObservation) {
        val existing = dao.lookup(geohash6, obs.mccMnc, obs.lac, obs.cid)
        val now = System.currentTimeMillis()
        val row = BaselineCell(
            geohash6 = geohash6,
            mccMnc = obs.mccMnc,
            lac = obs.lac,
            cid = obs.cid,
            rat = obs.rat,
            earfcn = obs.earfcn,
            tac = obs.tac,
            pci = obs.pci,
            signalDbm = obs.signalDbm,
            firstSeenMs = existing?.firstSeenMs ?: now,
            lastSeenMs = now,
            sightings = (existing?.sightings ?: 0) + 1,
        )
        dao.upsert(row)
    }

    suspend fun prune7d() {
        dao.prune(System.currentTimeMillis() - 7L * 24 * 3600 * 1000)
    }

    suspend fun hasModernRatHistory(geohash6: String): Boolean {
        val cells = dao.forGeohash(geohash6)
        return cells.any { it.rat == "LTE" || it.rat == "NR" }
    }
}
