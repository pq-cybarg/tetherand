package dev.tetherand.app.aiguard.phishing

/**
 * Deterministic primary for the "Inbound-message screen" defense.
 *
 * Scores text-message-shaped input for phishing intent on 4 axes:
 *   - urgency  ("urgent", "expires in X hours", "act now")
 *   - authority  ("we noticed", "from the team", official-tone)
 *   - financial-ask  ("verify card", "wire transfer", "gift card")
 *   - URL look-alike  (typo-squat of known brands, free TLDs, IDN homoglyphs)
 *
 * Two or more axes scoring high → Verdict.High. One axis → Medium.
 * No matches → Low.
 *
 * This is the deterministic primary; the spec's contributory layer
 * (phi-tetherand-3b-q4) refines via NLU classification but cannot
 * downgrade a deterministic High to Low.
 */
object PhishingRule {

    enum class Verdict { Low, Medium, High }

    data class Result(val verdict: Verdict, val reasons: List<String>, val urlsScanned: List<String>)

    private val urgencyRegex = Regex(
        "(?i)(urgent|immediately|expires?|suspended?|verify (now|today)|act now|within 24 (?:hours?|h))"
    )
    private val authorityRegex = Regex(
        "(?i)(we (?:noticed|detected)|security team|the (?:billing|fraud) (?:dept|department)|official notice)"
    )
    private val financialRegex = Regex(
        "(?i)(wire transfer|gift card|verify (your )?(card|account|bank)|reactivate.{0,20}billing|pay (?:overdue|owed))"
    )
    private val freeTldsRegex = Regex("(?i)\\b[\\w-]+\\.(tk|ml|ga|cf|gq|xyz|top|zip|mov)\\b")
    private val urlRegex = Regex("https?://[^\\s'\"<>]+")

    // Common brand domains we'd expect a typo of.
    private val brands = listOf(
        "amazon", "paypal", "microsoft", "apple", "google", "github",
        "coinbase", "binance", "phantom", "magiceden", "solana",
        "anthropic", "openai", "att", "verizon", "tmobile",
    )

    fun classify(text: String): Result {
        val reasons = mutableListOf<String>()
        var axes = 0

        if (urgencyRegex.containsMatchIn(text)) { reasons.add("urgency"); axes++ }
        if (authorityRegex.containsMatchIn(text)) { reasons.add("authority"); axes++ }
        if (financialRegex.containsMatchIn(text)) { reasons.add("financial-ask"); axes++ }
        if (freeTldsRegex.containsMatchIn(text)) { reasons.add("free-tld"); axes++ }

        // URL inspection.
        val urls = urlRegex.findAll(text).map { it.value }.toList()
        for (url in urls) {
            val host = hostOf(url) ?: continue
            for (b in brands) {
                if (host.contains(b)) continue       // legit brand mention
                if (looksLikeTypoOf(host, b)) {
                    reasons.add("typo-of-$b")
                    axes++
                }
            }
        }

        val v = when {
            axes >= 2 -> Verdict.High
            axes == 1 -> Verdict.Medium
            else      -> Verdict.Low
        }
        return Result(v, reasons.distinct(), urls)
    }

    private fun hostOf(url: String): String? = try {
        java.net.URI(url).host?.lowercase()
    } catch (_: Throwable) { null }

    /** Tiny Levenshtein for typo detection. Two strings within edit-distance
     *  2 *and* sharing >= 60% prefix overlap count as typo-of-other. */
    private fun looksLikeTypoOf(host: String, brand: String): Boolean {
        val tokens = host.split('.', '-')
        for (t in tokens) {
            if (t.length < 4) continue
            val d = levenshtein(t, brand)
            if (d in 1..2 && t.take(brand.length / 2) == brand.take(brand.length / 2)) return true
            // IDN homoglyph cheap-check: 0↔o, 1↔l, rn↔m.
            val n = t.replace('0', 'o').replace('1', 'l').replace("rn", "m")
            if (n == brand) return true
        }
        return false
    }

    private fun levenshtein(a: String, b: String): Int {
        val m = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) m[i][0] = i
        for (j in 0..b.length) m[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) {
            val cost = if (a[i - 1] == b[j - 1]) 0 else 1
            m[i][j] = minOf(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + cost)
        }
        return m[a.length][b.length]
    }
}
