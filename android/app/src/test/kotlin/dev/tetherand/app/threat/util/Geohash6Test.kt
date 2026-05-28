package dev.tetherand.app.threat.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class Geohash6Test {
    @Test fun `Las Vegas Strip encodes to 6 chars`() {
        val gh = Geohash6.encode(36.1147, -115.1728)
        // Should be a stable 6-char base-32 string in the 9q* range (NW hemisphere).
        assertEquals(6, gh.length)
        assert(gh.startsWith("9q")) { "expected 9q-prefix for North America, got $gh" }
    }

    @Test fun `nearby points share prefix`() {
        // ~80m apart on the LV Strip.
        val a = Geohash6.encode(36.1147, -115.1728)
        val b = Geohash6.encode(36.1148, -115.1727)
        // Same geohash6 cell — first 5 chars should match (full 6 may flip at cell boundary)
        assertEquals(a.take(5), b.take(5))
    }

    @Test fun `distant points produce different hashes`() {
        val sf = Geohash6.encode(37.7749, -122.4194)
        val lv = Geohash6.encode(36.1147, -115.1728)
        assert(sf != lv) { "SF $sf and LV $lv should not collide" }
    }

    @Test fun `length is exactly 6`() {
        assertEquals(6, Geohash6.encode(0.0, 0.0).length)
    }
}
