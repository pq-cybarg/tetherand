package dev.tetherand.app.hardened.deadman

import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Periodic "still alive" check while Hardened Mode is active.
 *
 * Behaviour:
 *   - Every [intervalMs] (default 30 minutes), arm a prompt.
 *   - The UI watches [armedSince] and shows a one-tap "I'm OK"
 *     acknowledgement card.
 *   - If the user doesn't acknowledge within [graceMs] (default
 *     5 minutes), the configured [Action] fires.
 *
 * Three actions are supported, ordered by severity:
 *   - Alert       — write a Critical alert to ThreatDb. Default.
 *   - Isolate     — open Airplane-mode settings. Manual flip.
 *   - Burn        — open the system Reset > Factory data reset
 *                   shortcut. Two-tap to confirm there too.
 *
 * The switch does NOT auto-wipe. Every destructive action still
 * requires a deliberate user confirmation in system Settings; this is
 * the same posture as the Hardened Mode incident-response runbook.
 *
 * State is held in EncryptedSharedPreferences so the configuration
 * survives reboots (Hardened Mode itself does not auto-resume on
 * reboot, but the deadman config should persist).
 */
class DeadmansSwitch(private val ctx: Context) {

    enum class Action { Alert, Isolate, Burn }

    data class Config(
        val enabled: Boolean = false,
        val intervalMinutes: Int = 30,
        val graceMinutes: Int = 5,
        val action: Action = Action.Alert,
    )

    private val key = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx, "tetherand-deadman", key,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    private val _armedSince = MutableStateFlow<Long?>(null)
    /** Non-null when the deadman has fired its prompt and is waiting
     *  for the user to acknowledge. Holds the System.currentTimeMillis()
     *  at which the prompt fired. */
    val armedSince: StateFlow<Long?> = _armedSince.asStateFlow()

    private val _lastFire = MutableStateFlow<String?>(null)
    val lastFire: StateFlow<String?> = _lastFire.asStateFlow()

    fun load(): Config = Config(
        enabled = prefs.getBoolean("enabled", false),
        intervalMinutes = prefs.getInt("interval_min", 30),
        graceMinutes = prefs.getInt("grace_min", 5),
        action = try { Action.valueOf(prefs.getString("action", "Alert") ?: "Alert") }
                 catch (_: Throwable) { Action.Alert },
    )

    fun save(cfg: Config) {
        prefs.edit()
            .putBoolean("enabled", cfg.enabled)
            .putInt("interval_min", cfg.intervalMinutes)
            .putInt("grace_min", cfg.graceMinutes)
            .putString("action", cfg.action.name)
            .apply()
    }

    /** Start the watchdog. Idempotent — re-entrant calls are no-ops. */
    fun start() {
        if (job?.isActive == true) return
        val cfg = load()
        if (!cfg.enabled) return
        job = scope.launch {
            while (isActive) {
                delay(cfg.intervalMinutes * 60_000L)
                _armedSince.value = System.currentTimeMillis()
                delay(cfg.graceMinutes * 60_000L)
                // Still armed at end of grace window → fire.
                if (_armedSince.value != null) {
                    fire(cfg.action)
                    _armedSince.value = null
                }
            }
        }
    }

    /** Called by the UI when the user taps "I'm OK". */
    fun acknowledge() { _armedSince.value = null }

    /** Stop the watchdog (Hardened Mode exit or user disable). */
    fun stop() {
        job?.cancel()
        job = null
        _armedSince.value = null
    }

    private suspend fun fire(action: Action) {
        val ts = System.currentTimeMillis()
        val ev = JSONObject().apply {
            put("action", action.name)
            put("fired_at_ms", ts)
        }
        // Always log the fire to ThreatDb, regardless of action.
        try {
            ThreatDb.get(ctx).alerts().insert(Alert(
                tsMs = ts,
                heuristic = Heuristic.Permission_Diff,
                severity = Severity.Critical,
                summary = "Dead-man's switch fired (action: ${action.name})",
                evidenceJson = ev.toString(),
                geohash6 = null,
            ))
        } catch (_: Throwable) {}
        _lastFire.value = "${action.name} at $ts"

        when (action) {
            Action.Alert -> { /* Already logged. */ }
            Action.Isolate -> try {
                ctx.startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (_: Throwable) {}
            Action.Burn -> try {
                ctx.startActivity(Intent(Settings.ACTION_PRIVACY_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (_: Throwable) {}
        }
    }
}
