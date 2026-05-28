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
            // Movement resets the stillness timer regardless of armed state.
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
