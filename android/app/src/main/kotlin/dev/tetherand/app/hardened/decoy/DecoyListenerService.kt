package dev.tetherand.app.hardened.decoy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.ServerSocket

/**
 * Honeypot. Binds a handful of unprivileged ports and logs every inbound
 * connection attempt as a Threat alert. A network scanner on the same
 * LAN (Wall of Sheep, Pineapple, etc.) hitting any of these ports gives
 * the user a clear "you are being probed" signal.
 *
 * Privileged ports (<1024) are skipped because Android doesn't grant
 * binds without root. We pick common scan targets that stock Android
 * apps don't legitimately use.
 */
class DecoyListenerService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val jobs = mutableListOf<Job>()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopAll(); return START_NOT_STICKY }
        startForegroundNotif()
        for (port in DECOY_PORTS) {
            jobs += scope.launch { listen(port) }
        }
        return START_STICKY
    }

    private suspend fun listen(port: Int) {
        try {
            ServerSocket(port).use { server ->
                server.soTimeout = 0
                while (scope.isActive) {
                    val sock = try { server.accept() } catch (_: Throwable) { break }
                    val peer = sock.inetAddress?.hostAddress ?: "unknown"
                    val tsMs = System.currentTimeMillis()
                    val ev = JSONObject().apply {
                        put("port", port)
                        put("peer", peer)
                    }
                    val alert = Alert(
                        tsMs = tsMs,
                        heuristic = Heuristic.Permission_Diff, // re-use as honeypot-hit tag in v1
                        severity = Severity.High,
                        summary = "Honeypot: connection attempt to :$port from $peer",
                        evidenceJson = ev.toString(),
                        geohash6 = null,
                    )
                    try { ThreatDb.get(applicationContext).alerts().insert(alert) }
                    catch (t: Throwable) { Log.w(TAG, "honeypot insert: $t") }
                    try { sock.close() } catch (_: Throwable) {}
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "decoy port $port failed: $t")
        }
    }

    private fun stopAll() {
        jobs.forEach { it.cancel() }
        jobs.clear()
        scope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startForegroundNotif() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Decoy listeners", NotificationManager.IMPORTANCE_LOW))
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(dev.tetherand.app.R.drawable.ic_report_problem_24dp)
            .setContentTitle("Tetherand honeypot")
            .setContentText("Listening on ${DECOY_PORTS.joinToString(",")}")
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    companion object {
        private const val TAG = "DecoyListener"
        const val CHANNEL_ID = "tetherand-decoy"
        const val NOTIF_ID = 0x7e81
        const val ACTION_STOP = "dev.tetherand.app.action.DECOY_STOP"
        val DECOY_PORTS = listOf(8080, 8443, 8000, 9000, 1080, 3128)
    }
}
