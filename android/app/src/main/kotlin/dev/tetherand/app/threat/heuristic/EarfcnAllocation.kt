package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.CellObservation
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject

/**
 * Crocodile Hunter: alert when the LTE EARFCN is outside the operator's
 * published allocation range for the user's MCC/MNC. Stingrays often
 * advertise on an out-of-band channel because they don't coordinate
 * with the carrier.
 *
 * MVP table: a few US carrier allocations baked in. Unknown operator →
 * no opinion (avoid false positives). A future task fetches the full
 * worldwide table as a quarterly bundle.
 *
 * Sources: 3GPP TS 36.101 band assignments + carrier-published bands.
 */
class EarfcnAllocation {
    fun evaluate(obs: CellObservation): Alert? {
        if (obs.rat != "LTE") return null
        val earfcn = obs.earfcn ?: return null
        val allowed = ALLOCATIONS[obs.mccMnc] ?: return null
        if (allowed.any { earfcn in it }) return null
        val ev = JSONObject().apply {
            put("mccMnc", obs.mccMnc)
            put("earfcn", earfcn)
            put("allowedRanges", allowed.joinToString(", ") { "${it.first}..${it.last}" })
        }
        return Alert(
            tsMs = System.currentTimeMillis(),
            heuristic = Heuristic.Earfcn_Out_Of_Range,
            severity = Severity.High,
            summary = "EARFCN $earfcn outside ${obs.mccMnc} allocation",
            evidenceJson = ev.toString(),
            geohash6 = null,
        )
    }

    companion object {
        // Coarse US allocations — extend per the spec's bundled quarterly table.
        private val ALLOCATIONS: Map<String, List<IntRange>> = mapOf(
            "310410" to listOf(2000..2199, 5180..5279, 9210..9659),  // AT&T
            "310260" to listOf(1950..2099, 8240..8689, 5730..5849),  // T-Mobile
            "311480" to listOf(5230..5379, 8665..8689, 66436..67335), // Verizon
        )
    }
}
