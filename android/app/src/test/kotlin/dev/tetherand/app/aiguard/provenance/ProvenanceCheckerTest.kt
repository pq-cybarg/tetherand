package dev.tetherand.app.aiguard.provenance

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ProvenanceCheckerTest {

    @Test fun no_provenance_returns_unknown() {
        // Minimal JPEG header (SOI + EOI), no APP segments.
        val jpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xD9.toByte())
        val r = ProvenanceChecker.check(jpeg, "image/jpeg")
        assertEquals(ProvenanceChecker.Verdict.Unknown, r.verdict)
    }

    @Test fun jumbf_marker_returns_c2pa() {
        // Synthetic JPEG with APP11 segment carrying "JUMB" identifier
        // + nested "c2pa" type. This is a structural-presence test, not a
        // signature-validity test; signature verification is documented
        // as out-of-scope for v1 (M10.x).
        val payload = "JUMB    c2pa".toByteArray(Charsets.ISO_8859_1)
        val app11 = byteArrayOf(0xFF.toByte(), 0xEB.toByte()) +
                    intToBE2(payload.size + 2) + payload
        val jpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte()) +
                   app11 +
                   byteArrayOf(0xFF.toByte(), 0xD9.toByte())
        val r = ProvenanceChecker.check(jpeg, "image/jpeg")
        assertEquals(ProvenanceChecker.Verdict.C2PA, r.verdict)
    }

    @Test fun synthid_marker_returns_synthid() {
        val raw = "some image bytes including SynthID metadata marker here.".toByteArray()
        val r = ProvenanceChecker.check(raw, "image/png")
        assertEquals(ProvenanceChecker.Verdict.SynthID, r.verdict)
    }

    private fun intToBE2(n: Int): ByteArray =
        byteArrayOf(((n shr 8) and 0xFF).toByte(), (n and 0xFF).toByte())
}
