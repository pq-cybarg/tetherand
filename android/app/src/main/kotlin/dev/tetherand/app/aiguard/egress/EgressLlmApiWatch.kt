package dev.tetherand.app.aiguard.egress

import android.content.Context
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import org.json.JSONObject

/**
 * Match outbound hostnames (SNI or DNS queries) against LlmApiWatchlist
 * and surface the match as a High-severity Alert.
 *
 * Wiring strategies:
 *   1. (M10) Manual scan: user pastes/imports a DNS-query log (e.g. from
 *      AdGuard, PCAPdroid) into the AI tab. We classify each entry.
 *   2. (M10.x) Online: the M3 chain's DNS resolver feeds every query
 *      through monitorObserved() before resolution. Surface in real time.
 *   3. (M10.x) VPN packet inspection: TetherandChainService taps the TUN
 *      stream, extracts ClientHello SNI, and feeds it here.
 *
 * v1 implements (1) end-to-end and exposes the API surface (2) and (3)
 * need to call into.
 */
object EgressLlmApiWatch {

    data class Hit(val host: String, val matchedBy: String, val tsMs: Long)

    /** Pure classifier. */
    fun classify(host: String): String? {
        val h = host.lowercase().trim().trimEnd('.')
        if (h in LlmApiWatchlist.EXACT) return "exact:$h"
        for (sfx in LlmApiWatchlist.SUFFIX) if (h.endsWith(sfx)) return "suffix:$sfx"
        return null
    }

    /** Scan a list of observed hostnames; fire alerts for hits, return them. */
    suspend fun scanAndAlert(ctx: Context, hosts: List<String>): List<Hit> {
        val dao = ThreatDb.get(ctx).alerts()
        val hits = mutableListOf<Hit>()
        val now = System.currentTimeMillis()
        for (h in hosts.distinct()) {
            val by = classify(h) ?: continue
            val hit = Hit(h, by, now)
            hits.add(hit)
            val ev = JSONObject().apply {
                put("host", h); put("matched_by", by)
            }
            dao.insert(Alert(
                tsMs = now,
                heuristic = Heuristic.Permission_Diff, // re-use as egress-llm-api tag
                severity = Severity.High,
                summary = "Egress LLM API: $h",
                evidenceJson = ev.toString(),
                geohash6 = null,
            ))
        }
        return hits
    }
}
