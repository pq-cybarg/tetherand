package dev.tetherand.app.aiguard.clipboard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ClipboardManager
import android.content.Context
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
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/**
 * Watch the system clipboard. When a prompt-injection scaffold is
 * detected, fire a High-severity Alert and surface a one-tap "clear
 * clipboard" action.
 *
 * Foreground service (subtype "clipboard_scrubber") because Android
 * restricts clipboard reads to foreground apps and default IMEs from
 * SDK 30+. As a foreground service we get the foreground criterion.
 *
 * We do NOT auto-clear the clipboard — that would be user-hostile and
 * break legitimate copy/paste of LLM transcripts. The user gets a banner
 * + Clear button.
 */
class ClipboardScrubberService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var clipboard: ClipboardManager
    private val listener = ClipboardManager.OnPrimaryClipChangedListener { onClipChanged() }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.addPrimaryClipChangedListener(listener)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopAll(); return START_NOT_STICKY }
        startForegroundNotif()
        return START_STICKY
    }

    private fun onClipChanged() {
        val clip = try { clipboard.primaryClip } catch (_: Throwable) { return } ?: return
        val text = clip.getItemAt(0).coerceToText(this)?.toString() ?: return
        val r = PromptInjectionRegex.scan(text)
        if (!r.detected) return
        scope.launch {
            val ev = JSONObject().apply {
                put("scaffolds", JSONArray(r.matched))
                put("len", text.length)
            }
            val alert = Alert(
                tsMs = System.currentTimeMillis(),
                heuristic = Heuristic.Permission_Diff, // re-use as scaffolding-hit tag
                severity = Severity.High,
                summary = "Prompt-injection scaffold detected in clipboard: ${r.matched.first().take(40)}",
                evidenceJson = ev.toString(),
                geohash6 = null,
            )
            try { ThreatDb.get(applicationContext).alerts().insert(alert) }
            catch (t: Throwable) { Log.w(TAG, "scrubber insert: $t") }
        }
    }

    private fun stopAll() {
        try { clipboard.removePrimaryClipChangedListener(listener) } catch (_: Throwable) {}
        scope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startForegroundNotif() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Clipboard scrubber", NotificationManager.IMPORTANCE_LOW))
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(dev.tetherand.app.R.drawable.ic_report_problem_24dp)
            .setContentTitle("Tetherand AI Guard")
            .setContentText("Watching clipboard for prompt-injection scaffolds")
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    companion object {
        private const val TAG = "ClipboardScrubber"
        const val CHANNEL_ID = "tetherand-clipboard"
        const val NOTIF_ID = 0x7e90
        const val ACTION_STOP = "dev.tetherand.app.action.CLIPBOARD_STOP"
    }
}
