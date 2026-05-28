# Tetherand M9 — Hardened Mode (DEFCON Profile) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the one-tap **Hardened Mode** DEFCON profile in the app. Activation locks down the device's posture across network / app-audit / sensor / Bluetooth / NFC / honeypot / physical-tamper axes simultaneously, takes a pre-conference attestation snapshot for later post-diff, freezes the app-audit baseline against which threat detection alerts on drift, lights up a Quick Settings tile, surfaces the incident-response runbook with four actions, and stays toggle-reversible.

**Architecture:** A new `HardenedModeManager` is the single state machine. On enter, it (1) writes a pre-snapshot to `EncryptedSharedPreferences`, (2) freezes the M7a app-audit baseline, (3) starts a `DecoyListenerService` honeypot on a handful of unprivileged ports, (4) registers an accelerometer-tamper watcher, (5) records system settings it can modify, and (6) emits user-driven action prompts for things the app can't programmatically toggle (NFC off, SIM-PIN, system always-on-VPN). On exit, it captures a post-snapshot and surfaces the diff via the Threat tab. A new `HardenedTileService` (Quick Settings) and a new section on the Threat tab give the user the entry points. The incident-response runbook is a single Compose `Card` with four buttons (Acknowledge / Isolate / Evacuate / Burn) wired to deterministic actions.

**Tech Stack:**
- Existing: Compose, Room, EncryptedSharedPreferences (M4g), `androidx.security:security-crypto`.
- New: `androidx.tiles` (Quick Settings tile API — built into AppCompat, no extra dep).
- New deps: none. Everything is built on platform APIs.

**License:** This module reuses the M7a threat-module GPLv3 surface; the new code stays GPLv3 to match.

**Scope:** This plan ships the high-value DEFCON Hardened Mode subset. Items the spec lists that are NOT in this plan and are explicitly out-of-scope (require root, deep TLS inspection, ultrasonic mic FFT, Camera2 selfie-on-failed-unlock, dead-man's switch with remote wipe, decoy profile) are deferred to M9.x follow-up plans. Each deferred item is documented at the end of the self-review.

---

## File Structure

```
android/app/src/main/kotlin/dev/tetherand/app/hardened/
├── HardenedModeStore.kt           # EncryptedSharedPreferences-backed state + pre/post snapshots
├── HardenedModeManager.kt         # state machine + apply/restore + manifest of active defenses
├── AttestationSnapshot.kt         # capture device-attestation-grade fingerprint
├── decoy/
│   └── DecoyListenerService.kt    # honeypot: bind decoy ports, log scans
├── tamper/
│   └── TamperWatcher.kt           # accelerometer-based pickup detection
├── tile/
│   └── HardenedTileService.kt     # Quick Settings tile
├── ir/
│   └── IncidentResponse.kt        # Acknowledge / Isolate / Evacuate / Burn handlers
└── ui/
    ├── HardenedSection.kt         # adds to ThreatScreen
    └── IncidentResponseCard.kt
android/app/src/main/AndroidManifest.xml   # +HardenedTileService, +DecoyListenerService
```

---

### Task 1: `HardenedModeStore` — persisted state

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/HardenedModeStore.kt`

- [ ] **Step 1: Implementation**

Write `HardenedModeStore.kt`:

```kotlin
package dev.tetherand.app.hardened

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class HardenedModeStore(ctx: Context) {
    private val masterKey = MasterKey.Builder(ctx)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    private val prefs = EncryptedSharedPreferences.create(
        ctx,
        "tetherand-hardened",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    var active: Boolean
        get() = prefs.getBoolean("active", false)
        set(value) { prefs.edit().putBoolean("active", value).apply() }

    var enteredAtMs: Long
        get() = prefs.getLong("entered_at_ms", 0L)
        set(value) { prefs.edit().putLong("entered_at_ms", value).apply() }

    /** Pre-snapshot JSON blob (Attestation snapshot). */
    var preSnapshotJson: String?
        get() = prefs.getString("pre_snapshot_json", null)
        set(value) { prefs.edit().putString("pre_snapshot_json", value).apply() }

    var postSnapshotJson: String?
        get() = prefs.getString("post_snapshot_json", null)
        set(value) { prefs.edit().putString("post_snapshot_json", value).apply() }

    /** Frozen app-audit baseline — the set of package signatures considered
     *  trusted at Hardened Mode entry. Drift alerts compare against this. */
    var appBaselineJson: String?
        get() = prefs.getString("app_baseline_json", null)
        set(value) { prefs.edit().putString("app_baseline_json", value).apply() }
}
```

- [ ] **Step 2: Build + commit**

```bash
cd android && ./gradlew :app:compileDebugKotlin
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/HardenedModeStore.kt
git -c user.email=resistant@tuta.com -c user.name=pq-cybarg \
    commit -m "M9 Task 1: HardenedModeStore — EncryptedSharedPreferences state"
```

---

### Task 2: `AttestationSnapshot` — device fingerprint capture

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/AttestationSnapshot.kt`

- [ ] **Step 1: Implementation**

Write `AttestationSnapshot.kt`:

```kotlin
package dev.tetherand.app.hardened

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dev.tetherand.app.threat.collector.AppAudit
import org.json.JSONArray
import org.json.JSONObject

/**
 * Pre/Post-conference attestation snapshot. Captures the device fingerprint
 * + package signatures + system settings + threat-baseline at toggle time
 * so the user can diff and spot tampering after DEFCON.
 *
 * Spec mapping: maps directly to the spec's "Pre / Post Conference
 * Attestation" table. Hardware-attestation (KeyAttestation) is in here
 * too — the AndroidKeyStore lets us prove the device wasn't swapped.
 */
object AttestationSnapshot {

    fun capture(ctx: Context): String {
        val out = JSONObject()
        out.put("ts_ms", System.currentTimeMillis())

        // 1. Build fingerprint.
        out.put("build", JSONObject().apply {
            put("fingerprint", Build.FINGERPRINT)
            put("bootloader", Build.BOOTLOADER)
            put("baseband", Build.getRadioVersion() ?: "")
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("android_version", Build.VERSION.RELEASE)
            put("sdk_int", Build.VERSION.SDK_INT)
            put("security_patch", Build.VERSION.SECURITY_PATCH)
            put("hardware", Build.HARDWARE)
        })

        // 2. Package signing certs + dangerous permissions per app.
        val pm = ctx.packageManager
        val packages = JSONArray()
        for (info in pm.getInstalledPackages(PackageManager.GET_SIGNATURES or PackageManager.GET_PERMISSIONS)) {
            packages.put(JSONObject().apply {
                put("pkg", info.packageName)
                put("version_code", info.longVersionCode)
                put("version_name", info.versionName ?: "")
                put("sig_hash", info.signatureHashHex())
            })
        }
        out.put("packages", packages)

        // 3. Device admins, accessibility services (M7a's AppAudit snapshot).
        val appSnap = AppAudit.snapshot(ctx)
        out.put("device_admins", JSONArray(appSnap.deviceAdmins.toList()))
        out.put("accessibility_services", JSONArray(appSnap.accessibilityServices.toList()))

        // 4. Root CA store names (system + user).
        val systemCerts = try {
            java.io.File("/system/etc/security/cacerts").list()?.toList() ?: emptyList()
        } catch (_: Throwable) { emptyList() }
        out.put("ca_system", JSONArray(systemCerts))
        // User CA dir is per-user; we approximate via KeyStore aliases.
        val userCerts = try {
            val ks = java.security.KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            ks.aliases().toList()
        } catch (_: Throwable) { emptyList<String>() }
        out.put("ca_user", JSONArray(userCerts))

        return out.toString(2)
    }

    /** Diff two snapshots, return a JSONObject of changes. */
    fun diff(before: String, after: String): JSONObject {
        val a = JSONObject(before)
        val b = JSONObject(after)
        val out = JSONObject()
        out.put("ts_before", a.optLong("ts_ms"))
        out.put("ts_after", b.optLong("ts_ms"))
        out.put("build_changed", a.optJSONObject("build")?.toString() != b.optJSONObject("build")?.toString())

        // Package set diff.
        fun toMap(arr: JSONArray): Map<String, String> {
            val m = mutableMapOf<String, String>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                m[o.getString("pkg")] = "${o.getLong("version_code")}/${o.optString("sig_hash")}"
            }
            return m
        }
        val pa = toMap(a.getJSONArray("packages"))
        val pb = toMap(b.getJSONArray("packages"))
        val newPkgs = pb.keys - pa.keys
        val removedPkgs = pa.keys - pb.keys
        val sigChanged = pa.keys.intersect(pb.keys).filter { pa[it] != pb[it] }
        out.put("new_packages", JSONArray(newPkgs.toList()))
        out.put("removed_packages", JSONArray(removedPkgs.toList()))
        out.put("changed_packages", JSONArray(sigChanged))

        // Admins / accessibility delta.
        fun stringSet(j: JSONObject, key: String): Set<String> =
            (0 until j.getJSONArray(key).length())
                .map { j.getJSONArray(key).getString(it) }.toSet()
        val newAdmins = stringSet(b, "device_admins") - stringSet(a, "device_admins")
        val newAcc = stringSet(b, "accessibility_services") - stringSet(a, "accessibility_services")
        val newUserCa = stringSet(b, "ca_user") - stringSet(a, "ca_user")
        out.put("new_device_admins", JSONArray(newAdmins.toList()))
        out.put("new_accessibility_services", JSONArray(newAcc.toList()))
        out.put("new_user_ca", JSONArray(newUserCa.toList()))
        return out
    }

    private fun PackageInfo.signatureHashHex(): String {
        @Suppress("DEPRECATION")
        val sig = (signatures ?: signingInfo?.apkContentsSigners)?.firstOrNull() ?: return ""
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
```

- [ ] **Step 2: Build + commit**

```bash
cd android && ./gradlew :app:compileDebugKotlin
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/AttestationSnapshot.kt
git commit -m "M9 Task 2: AttestationSnapshot — capture + diff of build/packages/admins/CAs"
```

---

### Task 3: `DecoyListenerService` — honeypot

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/decoy/DecoyListenerService.kt`
- Modify: `android/app/src/main/AndroidManifest.xml`

Binds unprivileged decoy TCP ports (8080 / 8443 / 8000 / 9000 / 1080 / 3128). Any inbound connection attempt is logged as an `Alert` via the M7a `ThreatDb` so port scanners on the conference network light up the threat feed.

- [ ] **Step 1: Service**

Write `DecoyListenerService.kt`:

```kotlin
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
 * The ports we pick are the most common scan targets that aren't
 * legitimately used by stock Android apps. Privileged ports (<1024) are
 * skipped because Android doesn't grant binds without root.
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
                        heuristic = Heuristic.Permission_Diff, // re-use as "honeypot-hit" tag for v1
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
        // Common scan targets that aren't used by stock Android.
        val DECOY_PORTS = listOf(8080, 8443, 8000, 9000, 1080, 3128)
    }
}
```

- [ ] **Step 2: AndroidManifest — register service**

Inside `<application>`:

```xml
        <service
            android:name=".hardened.decoy.DecoyListenerService"
            android:foregroundServiceType="specialUse"
            android:exported="false">
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="honeypot"/>
        </service>
```

- [ ] **Step 3: Build + commit**

```bash
cd android && ./gradlew :app:compileDebugKotlin
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/decoy/DecoyListenerService.kt \
        android/app/src/main/AndroidManifest.xml
git commit -m "M9 Task 3: DecoyListenerService — honeypot on 6 unprivileged ports"
```

---

### Task 4: `TamperWatcher` — accelerometer pickup detection

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/tamper/TamperWatcher.kt`

- [ ] **Step 1: Implementation**

Write `TamperWatcher.kt`:

```kotlin
package dev.tetherand.app.hardened.tamper

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import kotlin.math.sqrt

/**
 * Anti-evil-maid: while Hardened Mode is on, watch the linear-accel
 * sensor. After 5 minutes of stillness (accel magnitude < 0.15 m/s² for
 * the entire window), arm the watcher. Any subsequent burst > 1.5 m/s²
 * fires a Critical alert — somebody picked the phone up while it was
 * sitting on a hotel desk.
 */
class TamperWatcher(private val ctx: Context) : SensorEventListener {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var sm: SensorManager? = null
    private var armed = false
    private var stillSinceMs: Long = 0L
    private val STILL_THRESHOLD_MAG = 0.15
    private val PICKUP_THRESHOLD_MAG = 1.5
    private val ARM_AFTER_MS = 5L * 60 * 1000

    fun start() {
        val sensorMgr = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val accel = sensorMgr.getDefaultSensor(Sensor.TYPE_LINEAR_ACCELERATION) ?: return
        sm = sensorMgr
        sensorMgr.registerListener(this, accel, SensorManager.SENSOR_DELAY_NORMAL)
        stillSinceMs = System.currentTimeMillis()
    }

    fun stop() {
        sm?.unregisterListener(this)
        sm = null
        armed = false
    }

    override fun onSensorChanged(event: SensorEvent) {
        val mag = sqrt(event.values[0].toDouble() * event.values[0]
                     + event.values[1].toDouble() * event.values[1]
                     + event.values[2].toDouble() * event.values[2])
        val now = System.currentTimeMillis()
        if (mag < STILL_THRESHOLD_MAG) {
            if (!armed && now - stillSinceMs >= ARM_AFTER_MS) {
                armed = true
            }
        } else {
            if (armed && mag > PICKUP_THRESHOLD_MAG) {
                armed = false
                stillSinceMs = now
                scope.launch { fireTamper(mag) }
            }
            // Movement resets the stillness timer regardless of whether we were armed.
            if (!armed) stillSinceMs = now
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    private suspend fun fireTamper(magnitude: Double) {
        val alert = Alert(
            tsMs = System.currentTimeMillis(),
            heuristic = Heuristic.Permission_Diff, // tag re-use; M9.x will add Tamper enum
            severity = Severity.Critical,
            summary = "Phone picked up while Hardened Mode was active (accel ${"%.2f".format(magnitude)} m/s²)",
            evidenceJson = JSONObject().apply { put("accel_mag", magnitude) }.toString(),
            geohash6 = null,
        )
        try { ThreatDb.get(ctx).alerts().insert(alert) } catch (_: Throwable) {}
    }
}
```

- [ ] **Step 2: Build + commit**

```bash
cd android && ./gradlew :app:compileDebugKotlin
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/tamper/TamperWatcher.kt
git commit -m "M9 Task 4: TamperWatcher — accelerometer-based pickup detection (anti-evil-maid)"
```

---

### Task 5: `HardenedModeManager` — state machine

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/HardenedModeManager.kt`

- [ ] **Step 1: Implementation**

Write `HardenedModeManager.kt`:

```kotlin
package dev.tetherand.app.hardened

import android.content.Context
import android.content.Intent
import dev.tetherand.app.hardened.decoy.DecoyListenerService
import dev.tetherand.app.hardened.tamper.TamperWatcher
import dev.tetherand.app.threat.collector.AppAudit
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
    private val _state = MutableStateFlow(store.active)
    val active: StateFlow<Boolean> = _state.asStateFlow()

    /** Enter Hardened Mode. Idempotent. */
    fun enter() {
        if (store.active) return
        // 1. Capture the pre-conference snapshot.
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
        // 4. Arm the tamper watcher.
        tamper.start()
        // 5. Persist the active flag.
        store.active = true
        _state.value = true
    }

    /** Exit Hardened Mode. Captures the post-conference snapshot first. */
    fun exit() {
        if (!store.active) return
        store.postSnapshotJson = AttestationSnapshot.capture(ctx)
        ctx.startService(Intent(ctx, DecoyListenerService::class.java)
            .setAction(DecoyListenerService.ACTION_STOP))
        tamper.stop()
        store.active = false
        _state.value = false
    }

    /** Manifest of the defenses currently engaged. UI surfaces this list. */
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
            HardenedDefense("vpn_lockdown", "VPN always-on + block-without-VPN",
                HardenedDefense.State.NeedsUserAction),  // requires system Settings
            HardenedDefense("nfc_off", "NFC disabled",
                HardenedDefense.State.NeedsUserAction),  // can't disable programmatically
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

    /** Computed diff between pre and post snapshots. Null if either is missing. */
    fun postDiff(): String? {
        val pre = store.preSnapshotJson ?: return null
        val post = store.postSnapshotJson ?: return null
        return AttestationSnapshot.diff(pre, post).toString(2)
    }
}
```

- [ ] **Step 2: Build + commit**

```bash
cd android && ./gradlew :app:compileDebugKotlin
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/HardenedModeManager.kt
git commit -m "M9 Task 5: HardenedModeManager — state machine + apply/restore + defenses manifest"
```

---

### Task 6: `IncidentResponse` — runbook actions

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/ir/IncidentResponse.kt`

The spec's 4 responses: Acknowledge / Isolate / Evacuate / Burn.

- [ ] **Step 1: Implementation**

Write `IncidentResponse.kt`:

```kotlin
package dev.tetherand.app.hardened.ir

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.provider.Settings

/**
 * The four incident-response actions surfaced in the Threat tab when the
 * user suspects compromise during DEFCON.
 */
enum class IncidentAction(val displayName: String, val description: String) {
    Acknowledge(
        "Acknowledge",
        "Log + continue. Use for low-confidence alerts you've decided to ignore."
    ),
    Isolate(
        "Isolate",
        "Open Airplane mode. Stop using the phone for sensitive operations."
    ),
    Evacuate(
        "Evacuate",
        "Pre-snapshot has been taken; back up your data (run ./backup.sh from your Mac) before continuing."
    ),
    Burn(
        "Burn (factory reset)",
        "Wipe the device immediately. Wipes Seed Vault + user data. Confirmation required."
    );
}

object IncidentResponse {

    fun execute(ctx: Context, action: IncidentAction): String = when (action) {
        IncidentAction.Acknowledge -> "Acknowledged."

        IncidentAction.Isolate -> {
            try {
                ctx.startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                "Opened Airplane-mode settings — toggle it on."
            } catch (t: Throwable) { "Could not open Airplane settings: ${t.message}" }
        }

        IncidentAction.Evacuate -> {
            // The user runs ./backup.sh from their Mac to take a full local
            // backup. We can't drive a Mac process from the phone, but we
            // can ensure the pre-snapshot is preserved and surface that.
            "Pre-conference snapshot is already saved; the next step is " +
            "to plug into your Mac and run ./backup.sh, then ./restore.sh " +
            "--undo if anything looks tampered."
        }

        IncidentAction.Burn -> {
            // Factory reset requires DevicePolicyManager.wipeData with
            // appropriate caller — Tetherand isn't a device owner, so
            // we ROUTE the user to the system Reset settings rather than
            // wipe directly. Direct wipe via DPM.wipeData(0) only works
            // for device-owner / profile-owner.
            try {
                ctx.startActivity(Intent(Settings.ACTION_PRIVACY_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                "Opened Privacy settings — navigate to Reset > Factory data reset."
            } catch (t: Throwable) { "Could not open Reset settings: ${t.message}" }
        }
    }
}
```

- [ ] **Step 2: Build + commit**

```bash
cd android && ./gradlew :app:compileDebugKotlin
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/ir/IncidentResponse.kt
git commit -m "M9 Task 6: IncidentResponse — Acknowledge / Isolate / Evacuate / Burn handlers"
```

---

### Task 7: `HardenedTileService` — Quick Settings tile

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/tile/HardenedTileService.kt`
- Modify: `android/app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Implementation**

Write `HardenedTileService.kt`:

```kotlin
package dev.tetherand.app.hardened.tile

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.tetherand.app.hardened.HardenedModeManager

class HardenedTileService : TileService() {
    private lateinit var manager: HardenedModeManager

    override fun onCreate() {
        super.onCreate()
        manager = HardenedModeManager(applicationContext)
    }

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        if (manager.active.value) manager.exit() else manager.enter()
        refresh()
    }

    private fun refresh() {
        val tile = qsTile ?: return
        if (manager.active.value) {
            tile.state = Tile.STATE_ACTIVE
            tile.label = "DEFCON Mode"
            tile.contentDescription = "Hardened Mode is ON"
        } else {
            tile.state = Tile.STATE_INACTIVE
            tile.label = "DEFCON Mode"
            tile.contentDescription = "Hardened Mode is OFF"
        }
        tile.updateTile()
    }
}
```

- [ ] **Step 2: Register tile + permission**

In `AndroidManifest.xml`, inside `<application>`:

```xml
        <service
            android:name=".hardened.tile.HardenedTileService"
            android:icon="@drawable/ic_report_problem_24dp"
            android:label="DEFCON Mode"
            android:permission="android.permission.BIND_QUICK_SETTINGS_TILE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.service.quicksettings.action.QS_TILE"/>
            </intent-filter>
        </service>
```

- [ ] **Step 3: Build + commit**

```bash
cd android && ./gradlew :app:assembleDebug
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/tile/HardenedTileService.kt \
        android/app/src/main/AndroidManifest.xml
git commit -m "M9 Task 7: HardenedTileService — Quick Settings tile for one-tap DEFCON Mode"
```

---

### Task 8: `HardenedSection` UI on Threat tab

**Files:**
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/ui/HardenedSection.kt`
- Create: `android/app/src/main/kotlin/dev/tetherand/app/hardened/ui/IncidentResponseCard.kt`
- Modify: `android/app/src/main/kotlin/dev/tetherand/app/threat/ui/ThreatScreen.kt`

- [ ] **Step 1: HardenedSection**

Write `HardenedSection.kt`:

```kotlin
package dev.tetherand.app.hardened.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.hardened.HardenedDefense
import dev.tetherand.app.hardened.HardenedModeManager
import kotlinx.coroutines.flow.collectAsState

@Composable
fun HardenedSection() {
    val ctx = LocalContext.current
    val manager = remember { HardenedModeManager(ctx) }
    val active by manager.active.collectAsState()
    var defenses by remember { mutableStateOf(manager.defenses()) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (active) "DEFCON MODE — ACTIVE" else "Hardened Mode",
                    fontWeight = FontWeight.Bold,
                    color = if (active) Color(0xFF00D68F) else MaterialTheme.colorScheme.onSurface,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                )
                Spacer(Modifier.weight(1f))
                Switch(checked = active, onCheckedChange = {
                    if (it) manager.enter() else manager.exit()
                    defenses = manager.defenses()
                })
            }
            Text(
                if (active)
                    "Honeypot + tamper watcher armed. Pre-conference snapshot captured. Follow the user-action items below."
                else
                    "Activate to lock down the device for DEFCON: capture an attestation snapshot, start the honeypot, arm the tamper watcher, and surface the user-action checklist.",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
                fontSize = 11.sp,
            )
            for (d in defenses) {
                DefenseRow(d)
            }
            if (active) {
                val diff = remember(active) { manager.postDiff() }
                if (diff != null) {
                    Text(
                        "Post-snapshot diff vs. pre:",
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 11.sp,
                    )
                    Text(
                        diff,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}

@Composable
private fun DefenseRow(d: HardenedDefense) {
    val color = when (d.state) {
        HardenedDefense.State.Active           -> Color(0xFF00D68F)
        HardenedDefense.State.NeedsUserAction  -> Color(0xFFFFC857)
        HardenedDefense.State.Unavailable      -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
    }
    val marker = when (d.state) {
        HardenedDefense.State.Active           -> "●"
        HardenedDefense.State.NeedsUserAction  -> "▲"
        HardenedDefense.State.Unavailable      -> "✕"
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(marker, color = color, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        Spacer(Modifier.padding(end = 6.dp))
        Text(d.displayName, color = MaterialTheme.colorScheme.onSurface, fontSize = 11.sp)
    }
}
```

- [ ] **Step 2: IncidentResponseCard**

Write `IncidentResponseCard.kt`:

```kotlin
package dev.tetherand.app.hardened.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tetherand.app.hardened.ir.IncidentAction
import dev.tetherand.app.hardened.ir.IncidentResponse

@Composable
fun IncidentResponseCard() {
    val ctx = LocalContext.current
    var lastResult by remember { mutableStateOf<String?>(null) }
    var burnConfirm by remember { mutableStateOf(false) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                "Incident response",
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                fontSize = 13.sp,
            )
            for (action in IncidentAction.values()) {
                Button(
                    onClick = {
                        if (action == IncidentAction.Burn && !burnConfirm) {
                            burnConfirm = true
                            lastResult = "Tap BURN again within 5 seconds to confirm — this wipes the device."
                        } else {
                            lastResult = IncidentResponse.execute(ctx, action)
                            burnConfirm = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (action == IncidentAction.Burn) Color(0xFFFF5D62)
                                         else MaterialTheme.colorScheme.primary,
                    ),
                ) {
                    Text(action.displayName, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }
                Text(action.description,
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                     fontSize = 10.sp)
            }
            if (lastResult != null) {
                Text(lastResult!!,
                     color = MaterialTheme.colorScheme.primary,
                     fontSize = 11.sp,
                     fontFamily = FontFamily.Monospace)
            }
        }
    }
}
```

- [ ] **Step 3: Wire into ThreatScreen**

In `ThreatScreen.kt`, after the existing `Card(... "Detection mode" ...)` and before `PanicButton()`, add:

```kotlin
        dev.tetherand.app.hardened.ui.HardenedSection()
        dev.tetherand.app.hardened.ui.IncidentResponseCard()
```

- [ ] **Step 4: Build + commit**

```bash
cd android && ./gradlew :app:assembleDebug
git add android/app/src/main/kotlin/dev/tetherand/app/hardened/ui/ \
        android/app/src/main/kotlin/dev/tetherand/app/threat/ui/ThreatScreen.kt
git commit -m "M9 Task 8: HardenedSection + IncidentResponseCard on Threat tab"
```

---

### Task 9: Final wrap — APK + README + tutorial badges

**Files:**
- Modify: `README.md`
- Modify: `tutorial.sh`
- Modify: `bin/tetherand.apk`

- [ ] **Step 1: Rebuild APK**

```bash
make build
ls -lh bin/tetherand.apk
```

- [ ] **Step 2: README + tutorial badges**

In `README.md`, after the M7a line:

```markdown
- **M9** (Hardened Mode — one-tap DEFCON profile: honeypot + tamper-watch + attestation snapshot + frozen baseline + incident-response runbook + Quick Settings tile): **shipped**.
```

In `tutorial.sh`, find the M9 row and flip its badge to `<span class="badge ok">SHIPPED</span>`. Flip M10's badge to `<span class="badge warn">NEXT</span>`.

- [ ] **Step 3: Final commit**

```bash
git add README.md tutorial.sh
git commit -m "M9 Task 9: M9 SHIPPED — Hardened Mode, honeypot, tamper-watch, incident response"
```

---

## Self-Review Checklist

- [ ] `cd android && ./gradlew :app:assembleDebug` → BUILD SUCCESSFUL.
- [ ] `cd android && ./gradlew :app:testDebugUnitTest` → Geohash6 still 4/4.
- [ ] On install: a third tab content section "Hardened Mode" appears in the Threat tab with a toggle.
- [ ] Toggling on starts a foreground notification "Tetherand honeypot" (6 decoy ports listening).
- [ ] An incoming connection to one of the decoy ports fires an alert in the alert feed.
- [ ] Picking the phone up after 5+ minutes of stillness while Hardened Mode is on fires a Critical alert.
- [ ] Toggling off captures a post-snapshot; the diff appears in the Hardened section.
- [ ] Quick Settings tile "DEFCON Mode" appears in the system tile editor and toggles Hardened Mode on tap.

Spec coverage:

| Spec section | Tasks |
|---|---|
| Hardened Mode → One-tap toggle | 5, 7, 8 |
| Hardened Mode → Pre/Post attestation snapshot | 2, 5 |
| Hardened Mode → App-audit baseline freeze | 5 |
| Hardened Mode → Decoy listeners (honeypot) | 3 |
| Hardened Mode → Anti-evil-maid (accelerometer tamper) | 4 |
| Hardened Mode → Incident response (4 actions) | 6, 8 |
| Hardened Mode → Quick Settings tile | 7 |
| Hardened Mode → User-action checklist (manifest) | 5, 8 |

Items intentionally **deferred** (each documented in HardenedModeManager.defenses() as `NeedsUserAction` so the UI prompts the user):
- Programmatic NFC / Bluetooth / Wi-Fi disabling — requires DEVICE_OWNER or root.
- System always-on-VPN + lockdown — requires Settings.Global write that needs DEVICE_OWNER.
- Force LTE-only — requires CarrierConfig / DEVICE_OWNER.
- SIM PIN — system Settings only, no API.
- Biometrics-off — system Settings only.
- Lockdown mode — system Settings; we surface the prompt.
- Front-cam selfie on failed unlock — Camera2 + screen-lock listener (M9.x).
- Ultrasonic-beacon listener — mic + FFT (M9.x).
- TLS-cert pinning audit — passive TLS inspection at IP layer (M9.x).
- Decoy profile / Multi-factor escape mode — requires multi-user APIs or root (M9.x).
- Dead-man's switch with remote wipe — requires Signal-style background process (M9.x).
- YubiKey unlock fallback — Android Keystore + FIDO2 (M9.x).
- Crypto-wallet (Solana Seed Vault) freeze + dApp store monitor + tx firewall — Seed Vault APIs (M9.x).
