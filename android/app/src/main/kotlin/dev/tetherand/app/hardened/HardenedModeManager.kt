package dev.tetherand.app.hardened

import android.content.Context
import android.content.Intent
import dev.tetherand.app.aiguard.clipboard.ClipboardScrubberService
import dev.tetherand.app.hardened.deadman.DeadmansSwitch
import dev.tetherand.app.hardened.decoy.DecoyListenerService
import dev.tetherand.app.hardened.tamper.TamperWatcher
import dev.tetherand.app.hardened.ultrasonic.UltrasonicListener
import dev.tetherand.app.threat.collector.AppAudit
import dev.tetherand.app.threat.heuristic.ThreatSuppressions
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject

data class HardenedDefense(val id: String, val displayName: String, val state: State) {
    enum class State { Active, NeedsUserAction, Unavailable }
}

class HardenedModeManager(private val ctx: Context) {
    private val store = HardenedModeStore(ctx)
    private val tamper = TamperWatcher(ctx)
    private val ultrasonic = UltrasonicListener(ctx)
    val deadman = DeadmansSwitch(ctx)
    private val _state = MutableStateFlow(store.active)
    val active: StateFlow<Boolean> = _state.asStateFlow()

    /** Enter Hardened Mode. Idempotent. */
    fun enter() {
        if (store.active) return
        // 1. Pre-conference attestation snapshot.
        store.preSnapshotJson = AttestationSnapshot.capture(ctx)
        store.postSnapshotJson = null
        store.enteredAtMs = System.currentTimeMillis()
        // 2. Freeze the app-audit baseline.
        val snap = AppAudit.snapshot(ctx)
        store.appBaselineJson = JSONObject().apply {
            put("packages", JSONArray(snap.packages.keys.toList()))
            put("device_admins", JSONArray(snap.deviceAdmins.toList()))
            put("accessibility_services", JSONArray(snap.accessibilityServices.toList()))
        }.toString()
        // 3. Start the honeypot.
        ctx.startForegroundService(Intent(ctx, DecoyListenerService::class.java))
        // 3b. Start the M10 clipboard scrubber. While DEFCON Mode is on
        // we watch every clip change for prompt-injection scaffolds —
        // catches attacker-prepared text aimed at any LLM agent the user
        // happens to paste it into. Deterministic regex; no model needed.
        ctx.startForegroundService(Intent(ctx, ClipboardScrubberService::class.java))
        // 4. Arm the tamper watcher.
        tamper.start()
        // 4b. Start the dead-man's switch (no-op if disabled in its config).
        deadman.start()
        // 4c. Start the ultrasonic-beacon listener (no-op if RECORD_AUDIO missing).
        ultrasonic.start()
        // 4d. Wipe heuristic suppressions — DEFCON posture should be
        // strict, so any opt-outs the user set during dev work get
        // cleared on entry. They can re-enable individual ones after
        // confirming the conference environment is benign.
        ThreatSuppressions(ctx).clearAll()
        // 5. Persist + emit state.
        store.active = true
        _state.value = true
    }

    /** Exit Hardened Mode. Captures the post-conference snapshot first. */
    fun exit() {
        if (!store.active) return
        store.postSnapshotJson = AttestationSnapshot.capture(ctx)
        ctx.startService(Intent(ctx, DecoyListenerService::class.java)
            .setAction(DecoyListenerService.ACTION_STOP))
        ctx.startService(Intent(ctx, ClipboardScrubberService::class.java)
            .setAction(ClipboardScrubberService.ACTION_STOP))
        tamper.stop()
        ultrasonic.stop()
        deadman.stop()
        store.active = false
        _state.value = false
    }

    /** Manifest of defenses currently engaged. The UI surfaces this list. */
    fun defenses(): List<HardenedDefense> {
        val on = store.active
        return listOf(
            HardenedDefense("snapshot", "Pre-conference attestation captured",
                if (store.preSnapshotJson != null) HardenedDefense.State.Active else HardenedDefense.State.NeedsUserAction),
            HardenedDefense("baseline", "App-audit baseline frozen",
                if (store.appBaselineJson != null) HardenedDefense.State.Active else HardenedDefense.State.NeedsUserAction),
            HardenedDefense("honeypot", "Decoy listeners on 6 ports",
                if (on) HardenedDefense.State.Active else HardenedDefense.State.NeedsUserAction),
            HardenedDefense("tamper", "Accelerometer tamper-watcher armed",
                if (on) HardenedDefense.State.Active else HardenedDefense.State.NeedsUserAction),
            HardenedDefense("clipboard_scrubber", "Prompt-injection clipboard scrubber",
                if (on) HardenedDefense.State.Active else HardenedDefense.State.NeedsUserAction),
            HardenedDefense("ultrasonic", "Ultrasonic-beacon listener (18-22 kHz)",
                if (on) HardenedDefense.State.Active else HardenedDefense.State.NeedsUserAction),
            HardenedDefense("vpn_lockdown", "VPN always-on + block-without-VPN",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("nfc_off", "NFC disabled",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("bt_off", "Bluetooth disabled (allowlist excepted)",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("sim_pin", "SIM PIN required",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("wifi_forget", "All saved Wi-Fi forgotten",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("force_lte", "Force LTE-only (no 2G/3G)",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("biometrics_off", "Biometrics disabled — PIN only",
                HardenedDefense.State.NeedsUserAction),
            HardenedDefense("lockdown", "Android Lockdown Mode active",
                HardenedDefense.State.NeedsUserAction),
        )
    }

    /** Computed diff between pre and post snapshots. Null until both exist. */
    fun postDiff(): String? {
        val pre = store.preSnapshotJson ?: return null
        val post = store.postSnapshotJson ?: return null
        return AttestationSnapshot.diff(pre, post).toString(2)
    }
}
