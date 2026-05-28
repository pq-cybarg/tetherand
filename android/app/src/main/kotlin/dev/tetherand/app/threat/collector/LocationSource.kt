package dev.tetherand.app.threat.collector

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import androidx.core.content.ContextCompat
import dev.tetherand.app.threat.util.Geohash6
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Wraps the system LocationManager. Emits the current geohash6 whenever
 * a new GPS or network fix arrives. The geohash StateFlow stays null
 * until the first fix is delivered (or returns null when permission
 * is missing).
 */
class LocationSource(private val ctx: Context) {
    private val _geohash = MutableStateFlow<String?>(null)
    val geohash: StateFlow<String?> = _geohash.asStateFlow()
    private var listener: LocationListener? = null

    fun start() {
        if (!hasPermission()) return
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val l = LocationListener { loc -> _geohash.value = Geohash6.encode(loc.latitude, loc.longitude) }
        listener = l
        try {
            if (lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER))
                lm.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 30_000L, 50f, l)
            if (lm.isProviderEnabled(LocationManager.GPS_PROVIDER))
                lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 30_000L, 50f, l)
        } catch (_: SecurityException) {}
    }

    fun stop() {
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        listener?.let { try { lm.removeUpdates(it) } catch (_: Throwable) {} }
        listener = null
    }

    private fun hasPermission(): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

    /** Read the last-known fix synchronously (best-effort). */
    fun lastKnown(): Location? {
        if (!hasPermission()) return null
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return try {
            lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                ?: lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
        } catch (_: SecurityException) { null }
    }
}
