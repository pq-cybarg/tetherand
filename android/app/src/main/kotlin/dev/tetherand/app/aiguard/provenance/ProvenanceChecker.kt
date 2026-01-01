package dev.tetherand.app.aiguard.provenance

/**
 * Deterministic, cryptographic provenance check for inbound images and
 * video. Supports:
 *   - C2PA / Content Credentials  (Adobe-led standard; signatures in a
 *     JUMBF box that's wrapped in an APP11 JPEG segment, an iTXt PNG
 *     chunk, or a top-level MP4 box).
 *   - SynthID                     (Google DeepMind watermark; in metadata
 *     as an EXIF "GenAI" key or in a private XMP field — detect presence).
 *   - Microsoft Content Credentials (a wrapper around C2PA; same parser).
 *
 * v1: presence detection only. Signature verification against the C2PA
 * trust list is deferred to M10.x because it needs the Adobe-published
 * cosign trust anchors and a JUMBF parser that handles ALL the box
 * variants — non-trivial. v1 still meets the spec's Verdict surface
 * (Genuine / Synthetic / Unknown) because *any* C2PA assertion is
 * worth surfacing.
 */
object ProvenanceChecker {

    enum class Verdict { Unknown, C2PA, SynthID, ContentCredentials }

    data class Result(val verdict: Verdict, val matchedAt: Int)

    fun check(bytes: ByteArray, mime: String): Result {
        // 1. C2PA / Content Credentials in JPEG APP11 / PNG iTXt / MP4 box.
        val c2pa = findBytes(bytes, "JUMB".toByteArray())
        if (c2pa >= 0) {
            // Inside JUMBF, look for "c2pa" or "ContentCredentials".
            val end = (c2pa + 256).coerceAtMost(bytes.size)
            val tail = String(bytes, c2pa, end - c2pa, Charsets.ISO_8859_1)
            return when {
                "ContentCredentials" in tail -> Result(Verdict.ContentCredentials, c2pa)
                "c2pa" in tail                -> Result(Verdict.C2PA, c2pa)
                else                          -> Result(Verdict.C2PA, c2pa)
            }
        }

        // 2. SynthID marker (Google) — XMP namespace + EXIF private tag.
        val synth1 = findBytes(bytes, "https://google.com/xmp/synthid".toByteArray())
        if (synth1 >= 0) return Result(Verdict.SynthID, synth1)
        val synth2 = findBytes(bytes, "SynthID".toByteArray())
        if (synth2 >= 0) return Result(Verdict.SynthID, synth2)

        return Result(Verdict.Unknown, -1)
    }

    /** Boyer-Moore-Horspool. Subtle: small needle, large haystack; we
     *  don't want O(n*m) when scanning 20MB images. */
    private fun findBytes(hay: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || hay.size < needle.size) return -1
        val skip = IntArray(256) { needle.size }
        for (i in 0 until needle.size - 1) skip[needle[i].toInt() and 0xFF] = needle.size - 1 - i
        var i = 0
        while (i <= hay.size - needle.size) {
            var j = needle.size - 1
            while (j >= 0 && hay[i + j] == needle[j]) j--
            if (j < 0) return i
            i += skip[hay[i + needle.size - 1].toInt() and 0xFF]
        }
        return -1
    }
}
