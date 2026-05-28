package dev.tetherand.app.aiguard.perplexity

import kotlin.math.max
import kotlin.math.min

/**
 * Deterministic primary for the spec's "LLM-text 'AI?' badge" defense.
 *
 * Open-algorithm pseudo-perplexity: no neural component. Combines four
 * signals where humans systematically differ from LLM-generated text:
 *
 *   1. Average word length. LLM text averages 5+ chars per word due to
 *      formal vocabulary ("ensure", "effectively", "appreciate"); human
 *      casual writing averages 3-4 ("yo", "ngl", "the", "to").
 *   2. Function-word density. LLM text leans heavily on connectors
 *      ("that", "your", "we", "to", "the") for fluency; human text has
 *      proportionally more content nouns and verbs.
 *   3. First-person + colloquial markers. Human casual writing uses "i"
 *      / "yo" / "ngl" / "lol" / "wtf" / em-dashes; LLM text avoids them.
 *   4. Punctuation density. Human casual punctuation tends to burst
 *      ("...", "!!", "?!"); LLM text uses periods consistently.
 *
 * Each signal is normalized to [0, 1] (higher = more AI-like); the
 * final score is their mean. Purely heuristic and intentionally
 * advisory — the spec marks it as Contributory, not blocking.
 *
 * Inspired by the Binoculars approach (Hans et al. 2024) but without
 * requiring two LLMs to compute observed/expected perplexity ratios.
 */
object PerplexityRule {

    data class Score(
        val aiLikelihood: Double,        // [0, 1]
        val avgWordLengthScore: Double,
        val functionWordScore: Double,
        val colloquialScore: Double,
        val punctuationScore: Double,
    )

    // Common English function words — high frequency in LLM text.
    private val FUNCTION_WORDS: Set<String> = setOf(
        "the", "and", "of", "to", "in", "that", "we", "you", "your",
        "for", "with", "this", "is", "are", "was", "be", "have", "has",
        "would", "should", "please", "thank", "additional", "ensure",
        "provide", "address", "concerns", "patience", "understanding",
        "appreciate", "effectively", "assist", "further",
    )

    // Human-casual markers. Even one of these strongly biases human-side.
    private val COLLOQUIAL_MARKERS: Set<String> = setOf(
        "yo", "lol", "lmao", "ngl", "tbh", "wtf", "omg", "btw", "rn",
        "idk", "imo", "afaik", "ish", "kinda", "gonna", "wanna", "ya",
        "ima", "fr", "ong", "wya", "bc", "smh", "rofl", "iirc",
    )

    fun score(text: String): Score {
        if (text.isBlank()) return Score(0.5, 0.5, 0.5, 0.5, 0.5)
        val t = text.lowercase().replace(Regex("\\s+"), " ").trim()
        val words = t.split(Regex("[^a-z0-9']+")).filter { it.isNotEmpty() }
        if (words.isEmpty()) return Score(0.5, 0.5, 0.5, 0.5, 0.5)

        // 1. Average word length. <3.8 ≈ human; >4.8 ≈ LLM.
        val avgLen = words.sumOf { it.length.toDouble() } / words.size
        val avgLenAi = clamp01((avgLen - 3.8) / 1.4)

        // 2. Function-word density. <0.20 ≈ human; >0.30 ≈ LLM.
        val funcRatio = words.count { it in FUNCTION_WORDS }.toDouble() / words.size
        val funcAi = clamp01((funcRatio - 0.20) / 0.15)

        // 3. Colloquial markers. Any hit → strongly human.
        val collHits = words.count { it in COLLOQUIAL_MARKERS }
        val emDashes = text.count { it == '—' || it == '–' }
        val collScore = if (collHits + emDashes > 0) 0.05 else 0.6

        // 4. Punctuation density. Human casual: ~0.06; LLM: ~0.02.
        val punct = text.count { it in "!?.,;:—-…" }.toDouble() / max(1, text.length)
        val punctAi = clamp01(1.0 - punct / 0.05)

        val combined = (avgLenAi + funcAi + collScore + punctAi) / 4.0
        return Score(combined, avgLenAi, funcAi, collScore, punctAi)
    }

    private fun clamp01(x: Double): Double = max(0.0, min(1.0, x))
}
