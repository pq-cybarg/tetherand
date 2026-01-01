package dev.tetherand.app.threat.util

/** Standard base-32 geohash, fixed 6-character length (~1.2km × 0.6km cells). */
object Geohash6 {
    private const val BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"
    private const val PRECISION = 6

    fun encode(lat: Double, lon: Double): String {
        var latLo = -90.0; var latHi = 90.0
        var lonLo = -180.0; var lonHi = 180.0
        val sb = StringBuilder(PRECISION)
        var bit = 0
        var ch = 0
        var even = true
        while (sb.length < PRECISION) {
            if (even) {
                val mid = (lonLo + lonHi) / 2
                if (lon >= mid) { ch = ch or (1 shl (4 - bit)); lonLo = mid } else { lonHi = mid }
            } else {
                val mid = (latLo + latHi) / 2
                if (lat >= mid) { ch = ch or (1 shl (4 - bit)); latLo = mid } else { latHi = mid }
            }
            even = !even
            if (bit < 4) {
                bit++
            } else {
                sb.append(BASE32[ch])
                ch = 0
                bit = 0
            }
        }
        return sb.toString()
    }
}
