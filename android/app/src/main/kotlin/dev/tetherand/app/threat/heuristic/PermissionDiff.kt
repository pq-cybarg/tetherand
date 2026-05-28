package dev.tetherand.app.threat.heuristic

import dev.tetherand.app.threat.collector.AppSnapshot
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONArray
import org.json.JSONObject

/**
 * Compares two app snapshots. Fires when:
 *   • A new app appears (Medium).
 *   • An existing app gained any dangerous permission (Medium).
 *   • A new device-admin or accessibility-service was registered
 *     (Critical — both are common malware-persistence vectors).
 */
class PermissionDiff {
    fun evaluate(previous: AppSnapshot, current: AppSnapshot): List<Alert> {
        val out = mutableListOf<Alert>()
        val newPkgs = current.packages.keys - previous.packages.keys
        for (p in newPkgs) {
            out += Alert(
                tsMs = current.tsMs,
                heuristic = Heuristic.Permission_Diff,
                severity = Severity.Medium,
                summary = "New app installed: $p",
                evidenceJson = JSONObject().apply { put("pkg", p) }.toString(),
                geohash6 = null,
            )
        }
        for ((pkg, cur) in current.packages) {
            val old = previous.packages[pkg] ?: continue
            val gained = cur.grantedDangerous - old.grantedDangerous
            if (gained.isNotEmpty()) {
                val ev = JSONObject().apply {
                    put("pkg", pkg)
                    put("gained", JSONArray(gained.toList()))
                }
                out += Alert(
                    tsMs = current.tsMs,
                    heuristic = Heuristic.Permission_Diff,
                    severity = Severity.Medium,
                    summary = "$pkg gained ${gained.size} dangerous permission(s)",
                    evidenceJson = ev.toString(),
                    geohash6 = null,
                )
            }
        }
        val newAdmins = current.deviceAdmins - previous.deviceAdmins
        for (a in newAdmins) {
            out += Alert(
                tsMs = current.tsMs,
                heuristic = Heuristic.Permission_Diff,
                severity = Severity.Critical,
                summary = "New device-admin enrolled: $a",
                evidenceJson = JSONObject().apply { put("pkg", a) }.toString(),
                geohash6 = null,
            )
        }
        val newAcc = current.accessibilityServices - previous.accessibilityServices
        for (a in newAcc) {
            out += Alert(
                tsMs = current.tsMs,
                heuristic = Heuristic.Permission_Diff,
                severity = Severity.Critical,
                summary = "New accessibility service: $a",
                evidenceJson = JSONObject().apply { put("pkg", a) }.toString(),
                geohash6 = null,
            )
        }
        return out
    }
}
