package dev.tetherand.app.threat.heuristic

import android.content.Context
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import org.json.JSONObject
import java.io.File

/**
 * Detect whether `adbd` is exposing its protocol on a network socket.
 *
 * Motivated by CVE-2026-0073: the May 2026 ASB documents a Critical
 * RCE against the adbd debug interface affecting Android 14/15/16.
 * The unauthenticated network surface (TCP 5555, configurable via
 * `service.adb.tcp.port`) is the way this gets reached without USB
 * access. If we see adbd bound to anything other than loopback /
 * not-bound, that's a Critical signal.
 *
 * Detection signal:
 *   - `/proc/net/tcp` and `/proc/net/tcp6` enumerate every IPv4/IPv6
 *     listening socket on the device. Entries with state 0A (LISTEN)
 *     bound to port 0x15B3 (5555) or to a configured ADB-over-TCP
 *     port are flagged.
 *   - The system property `service.adb.tcp.port` (when set to a
 *     positive value) is itself the gate: presence of this property
 *     with a non-zero value is the explicit toggle that turns ADB
 *     network mode on, regardless of which port LISTENs.
 */
object AdbdNetworkSurface {

    const val id = "adbd-network-surface"

    private const val ADB_DEFAULT_PORT = 5555

    fun evaluate(ctx: Context): Alert? {
        if (ThreatSuppressions(ctx).isSuppressed(ThreatSuppressions.KEY_ADBD_NETWORK)) return null
        val tcpPortProp = systemProp("service.adb.tcp.port")?.toIntOrNull() ?: 0
        val listening = scanListenPorts()
        val adbPortsListening = listening.filter {
            it == ADB_DEFAULT_PORT || (tcpPortProp > 0 && it == tcpPortProp)
        }
        // Two ways this fires:
        //   1. The toggle is explicitly on (service.adb.tcp.port > 0).
        //   2. A socket is actually listening on the ADB-default port.
        // Plain USB ADB does NOT trip either branch (the USB transport
        // doesn't open a TCP listener and the property stays at 0/-1),
        // so `adb reverse` from `tetherand run` is invisible here. A
        // developer who deliberately enabled `adb tcpip` for their
        // own debug workflow can suppress via Threat tab once.
        if (tcpPortProp <= 0 && adbPortsListening.isEmpty()) return null

        val ev = JSONObject().apply {
            put("service.adb.tcp.port", tcpPortProp)
            put("listening_ports", adbPortsListening.joinToString(","))
            put("cve_context", "CVE-2026-0073")
        }
        return Alert(
            tsMs = System.currentTimeMillis(),
            heuristic = Heuristic.Permission_Diff,
            severity = Severity.Critical,
            summary = "adbd exposing network surface (CVE-2026-0073 RCE vector)",
            evidenceJson = ev.toString(),
            geohash6 = null,
        )
    }

    /** Read every TCP-LISTEN entry from /proc/net/tcp{,6}; return the
     *  local port numbers. Returns empty on permission denied. */
    private fun scanListenPorts(): List<Int> {
        val out = mutableListOf<Int>()
        for (path in listOf("/proc/net/tcp", "/proc/net/tcp6")) {
            val f = File(path)
            if (!f.canRead()) continue
            try {
                f.bufferedReader().useLines { lines ->
                    for (line in lines.drop(1)) {
                        // Format: sl  local_address rem_address st  ...
                        // local_address is HEX_IP:HEX_PORT
                        val cols = line.trim().split(Regex("\\s+"))
                        if (cols.size < 4) continue
                        val state = cols[3]
                        if (state != "0A") continue   // LISTEN only
                        val local = cols[1]
                        val colon = local.lastIndexOf(':')
                        if (colon < 0) continue
                        val port = local.substring(colon + 1).toIntOrNull(16) ?: continue
                        out.add(port)
                    }
                }
            } catch (_: Throwable) {}
        }
        return out
    }

    private fun systemProp(key: String): String? = try {
        val cls = Class.forName("android.os.SystemProperties")
        val m = cls.getMethod("get", String::class.java)
        (m.invoke(null, key) as? String)?.takeIf { it.isNotEmpty() }
    } catch (_: Throwable) { null }
}
