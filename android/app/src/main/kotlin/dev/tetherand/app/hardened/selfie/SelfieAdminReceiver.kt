package dev.tetherand.app.hardened.selfie

import android.app.admin.DeviceAdminReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Anti-evil-maid Camera2 trigger.
 *
 * Receives the system's `onPasswordFailed` callback whenever someone
 * enters the wrong PIN / pattern / password at the keyguard. Each
 * failure fires a single front-camera still capture into app-private
 * storage and logs an Alert.
 *
 * The user must enable this app as a Device Admin once via
 * Settings → Security → Device admin apps. The device-admin XML at
 * `res/xml/selfie_device_admin.xml` requests only `watch-login` —
 * the minimum policy needed for `onPasswordFailed`. We don't ask for
 * `force-lock`, `wipe-data`, or any other elevated capability.
 *
 * Deprecated-in-name, still-works-in-practice: `DeviceAdminReceiver`
 * was deprecated for "enterprise" use cases in Android 11+, but
 * personal-app device-admin enrollment still works on modern Android,
 * and `onPasswordFailed` continues to fire.
 */
class SelfieAdminReceiver : DeviceAdminReceiver() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onPasswordFailed(ctx: Context, intent: Intent) {
        super.onPasswordFailed(ctx, intent)
        // Don't block the receiver thread. The capture path itself
        // touches Camera2, file I/O, and the ThreatDb; all of that
        // happens off-thread.
        scope.launch {
            val store = SelfieStore(ctx)
            if (!store.enabled) return@launch
            val img = SelfieCaptor.captureFront(ctx)
            val savedTo: String? = img?.let { store.save(it) }
            val ev = JSONObject().apply {
                put("captured", savedTo != null)
                put("path", savedTo)
                put("attempts_so_far", store.incrementCount())
            }
            try {
                ThreatDb.get(ctx).alerts().insert(Alert(
                    tsMs = System.currentTimeMillis(),
                    heuristic = Heuristic.Permission_Diff,
                    severity = Severity.Critical,
                    summary = if (savedTo != null) {
                        "Failed unlock attempt — selfie captured (#${store.count})"
                    } else {
                        "Failed unlock attempt — selfie capture failed (camera unavailable)"
                    },
                    evidenceJson = ev.toString(),
                    geohash6 = null,
                ))
            } catch (_: Throwable) {}
        }
    }

    override fun onPasswordSucceeded(ctx: Context, intent: Intent) {
        super.onPasswordSucceeded(ctx, intent)
        // Reset the running attempt counter — a successful unlock
        // bounds the alert thread. We keep the saved selfies on disk
        // so the user can review what they look like after the fact.
        SelfieStore(ctx).resetCount()
    }

    companion object {
        /** Convenience for prompting the user to grant Device-Admin. */
        fun component(ctx: Context): ComponentName =
            ComponentName(ctx, SelfieAdminReceiver::class.java)
    }
}
