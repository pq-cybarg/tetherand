package dev.tetherand.app.threat.service

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
import dev.tetherand.app.threat.collector.AppAudit
import dev.tetherand.app.threat.collector.AppSnapshot
import dev.tetherand.app.threat.collector.BluetoothScanner
import dev.tetherand.app.threat.collector.CellInfoSource
import dev.tetherand.app.threat.collector.LocationSource
import dev.tetherand.app.threat.collector.WifiScanner
import dev.tetherand.app.threat.heuristic.BaselineStore
import dev.tetherand.app.threat.heuristic.BtsAlgorithm
import dev.tetherand.app.threat.heuristic.EarfcnAllocation
import dev.tetherand.app.threat.heuristic.EvilTwinWifi
import dev.tetherand.app.threat.heuristic.PermissionDiff
import dev.tetherand.app.threat.heuristic.RatDowngrade
import dev.tetherand.app.threat.heuristic.ReattachStorm
import dev.tetherand.app.threat.heuristic.TacChangeNoMotion
import dev.tetherand.app.threat.model.Alert
import dev.tetherand.app.threat.model.Heuristic
import dev.tetherand.app.threat.model.Severity
import dev.tetherand.app.threat.model.ThreatDb
import dev.tetherand.app.threat.sdr.SdrCellularProbe
import dev.tetherand.app.threat.util.Geohash6
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class ThreatDetectionService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var db: ThreatDb
    private lateinit var location: LocationSource
    private lateinit var cellSource: CellInfoSource
    private lateinit var wifi: WifiScanner
    private lateinit var bt: BluetoothScanner

    private lateinit var baseline: BaselineStore
    private val bts by lazy { BtsAlgorithm(baseline) }
    private val rat by lazy { RatDowngrade(baseline) }
    private val tac = TacChangeNoMotion()
    private val earfcn = EarfcnAllocation()
    private val storm = ReattachStorm()
    private val twin = EvilTwinWifi()
    private val permDiff = PermissionDiff()
    /** SDR-driven cellular-band RSSI probe (M7b mid-tier). Lazy
     *  so the System.loadLibrary("tetherand_sdr") inside the
     *  companion fires only when the service actually starts —
     *  important because not every device has the SDR .so and we
     *  want construct-without-load semantics elsewhere. */
    private val sdrProbe by lazy { SdrCellularProbe(applicationContext) }

    private var lastSnapshot: AppSnapshot? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        db = ThreatDb.get(this)
        baseline = BaselineStore(db.baselineCells())
        location = LocationSource(applicationContext)
        cellSource = CellInfoSource(applicationContext)
        wifi = WifiScanner(applicationContext)
        bt = BluetoothScanner(applicationContext)
        startForegroundNotif()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stop(); return START_NOT_STICKY }
        start()
        return START_STICKY
    }

    private fun start() {
        location.start()
        bt.start()
        lastSnapshot = AppAudit.snapshot(applicationContext)
        // Cell sampling every 5s.
        scope.launch {
            while (isActive) {
                cellSource.sample()
                runCellHeuristics()
                delay(5_000)
            }
        }
        // Wi-Fi every 30s.
        scope.launch {
            while (isActive) {
                runWifiHeuristics()
                delay(30_000)
            }
        }
        // App audit every 60s.
        scope.launch {
            while (isActive) {
                delay(60_000)
                runAppAudit()
            }
        }
        // BT trackers every 60s (the scanner runs continuously low-power;
        // we just sample its accumulated sightings here).
        scope.launch {
            while (isActive) {
                delay(60_000)
                bt.flagged().forEach { fire(it) }
            }
        }
        // Baseline maintenance daily.
        scope.launch {
            while (isActive) {
                delay(24L * 3600 * 1000)
                baseline.prune7d()
                db.alerts().prune(System.currentTimeMillis() - 30L * 24 * 3600 * 1000)
            }
        }
        // CVE-class heuristics: patch-level staleness + adbd-network
        // surface. These are slow-changing properties so we re-evaluate
        // every 6 hours; if anything fires it's typically a one-shot
        // alert until the user takes action.
        scope.launch {
            while (isActive) {
                dev.tetherand.app.threat.heuristic.PatchLevelStaleness.evaluate(applicationContext)?.let { fire(it) }
                dev.tetherand.app.threat.heuristic.AdbdNetworkSurface.evaluate(applicationContext)?.let { fire(it) }
                delay(6L * 3600 * 1000)
            }
        }
        // SDR-driven cellular-band RSSI sweep every 60 s. When no
        // RTL-SDR is attached the probe returns emptyList() cheaply;
        // when one IS attached the sweep produces a per-band dBm
        // table that the existing anomaly threshold (currently a
        // crude +20 dBm above a rolling baseline) converts into
        // alerts. The full anomaly classifier with the rolling
        // baseline lives in M7b.x alongside the srsRAN decoder;
        // v0.1 emits a logcat-only "sdr sweep" line per band when
        // dBm is non-NaN — sufficient to validate the JNI surface
        // empirically on a hardware-attached device.
        scope.launch {
            while (isActive) {
                runSdrHeuristics()
                delay(60_000)
            }
        }
    }

    private suspend fun runSdrHeuristics() {
        val readings = sdrProbe.snapshot()
        if (readings.isEmpty()) return  // no SDR attached
        for (r in readings) {
            if (r.dBm.isNaN()) continue
            Log.i(TAG, "sdr sweep: ${r.band} @ ${r.centerMhz} MHz → ${"%.1f".format(r.dBm)} dBm")
            // Crude threshold: +20 dBm above a fixed "quiet"
            // floor of -80 dBm. A future patch replaces the
            // floor with a per-band rolling baseline (same
            // pattern as BaselineStore for the cell tower data).
            if (r.dBm > -60f) {
                fire(
                    Alert(
                        tsMs = System.currentTimeMillis(),
                        heuristic = Heuristic.Sdr_Cellular_Anomaly,
                        severity = Severity.Medium,
                        summary = "SDR: elevated energy on ${r.band} (${"%.1f".format(r.dBm)} dBm)",
                        evidenceJson = """{"band":"${r.band}","center_mhz":${r.centerMhz},"dbm":${r.dBm}}""",
                        geohash6 = null,
                    )
                )
            }
        }
    }

    private suspend fun runCellHeuristics() {
        val gh = location.geohash.value
            ?: location.lastKnown()?.let { Geohash6.encode(it.latitude, it.longitude) }
            ?: return  // no location yet → skip; we'd produce noise without a baseline anchor
        val obs = cellSource.observations.value
        if (obs.isEmpty()) return

        for (o in obs) {
            bts.evaluate(gh, o)?.let { fire(it) }
            tac.evaluate(o, location.lastKnown())?.let { fire(it) }
            earfcn.evaluate(o)?.let { fire(it) }
            storm.evaluate(o)?.let { fire(it) }
            baseline.observe(gh, o)
        }
        rat.evaluate(gh, obs)?.let { fire(it) }
    }

    private fun runWifiHeuristics() {
        twin.evaluate(wifi.snapshot()).forEach { alert ->
            scope.launch { fire(alert) }
        }
    }

    private suspend fun runAppAudit() {
        val prev = lastSnapshot ?: return
        val cur = AppAudit.snapshot(applicationContext)
        permDiff.evaluate(prev, cur).forEach { fire(it) }
        lastSnapshot = cur
    }

    private suspend fun fire(alert: Alert) {
        try { db.alerts().insert(alert) } catch (t: Throwable) { Log.w(TAG, "alert insert: $t") }
    }

    private fun stop() {
        scope.cancel()
        location.stop()
        bt.stop()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startForegroundNotif() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Threat detection", NotificationManager.IMPORTANCE_LOW))
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(dev.tetherand.app.R.drawable.ic_report_problem_24dp)
            .setContentTitle("Tetherand threat detection")
            .setContentText("Watching cellular / Wi-Fi / Bluetooth / apps")
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    companion object {
        private const val TAG = "ThreatDetection"
        const val CHANNEL_ID = "tetherand-threat"
        const val NOTIF_ID = 0x7e80
        const val ACTION_STOP = "dev.tetherand.app.action.THREAT_STOP"
    }
}
