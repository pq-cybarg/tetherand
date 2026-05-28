package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.CellObservation
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * Crocodile Hunter: count distinct cell IDs observed in a rolling
 * 60-second window. > 4 distinct cells while stationary = re-attach
 * storm pattern (Stingray sweeping nearby phones onto its fake cell).
 */
class ReattachStorm {
    private val window = ArrayDeque<Pair<Long, Long>>()  // (tsMs, cid)

    fun evaluate(obs: CellObservation): Alert? {
        val now = obs.tsMs
        window.addLast(now to obs.cid)
        while (window.isNotEmpty() && window.first().first < now - 60_000) {
            window.removeFirst()
        }
        val distinct = window.map { it.second }.toSet().size
        if (distinct <= 4) return null
        val ev = JSONObject().apply {
            put("distinctCells60s", distinct)
            put("cids", window.map { it.second }.distinct().joinToString(","))
        }
        return Alert(
            tsMs = now,
            heuristic = Heuristic.Reattach_Storm,
            severity = Severity.Critical,
            summary = "Re-attach storm: $distinct distinct cells in 60s",
            evidenceJson = ev.toString(),
            geohash6 = null,
        )
    }
}
