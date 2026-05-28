package dev.tetherand.app.aiguard.clipboard

/**
 * Catalogue of prompt-injection scaffolds — text patterns commonly used
 * to override the system prompt of an LLM that the *user's other app*
 * pastes the clipboard into.
 *
 * Sources: OWASP LLM Top 10 (LLM01 Prompt Injection), Microsoft Purview
 * AI prompt-shield rules, Anthropic's published "common injection
 * primers". The list is intentionally narrow — every entry is a strong
 * signal because false-positive clipboard scrubs are user-hostile.
 *
 * Update path: bundled in-APK as ASCII; updated only through active
 * Privacy Chain via the M10.x delta mechanism (cosign-signed).
 */
object PromptInjectionRegex {

    data class Result(val detected: Boolean, val matched: List<String>)

    // Each regex is case-insensitive. We compile lazily on first use.
    private val patterns: List<Regex> = listOf(
        // Classic instruction-override.
        Regex("(?i)ignore (?:all )?previous instructions?"),
        Regex("(?i)disregard (?:all )?previous instructions?"),
        Regex("(?i)forget (?:all )?previous instructions?"),
        // Role / persona hijack.
        Regex("(?i)you are now (?:dan|stan|aim|developer mode)"),
        Regex("(?i)act as (?:dan|jailbreak|opposite mode)"),
        // System-prompt extract requests.
        Regex("(?i)reveal (?:your )?system prompt"),
        Regex("(?i)what (?:are|were) your (?:original|initial) instructions"),
        // Chat-template injection markers.
        Regex("<\\|im_start\\|>"),
        Regex("<\\|im_end\\|>"),
        Regex("\\[INST\\]"),
        Regex("\\[/INST\\]"),
        Regex("(?i)<system>"),
        Regex("(?i)<\\/system>"),
        Regex("(?i)\\bsystem:\\s+you (?:are|must|will)"),
        // Indirect-injection delimiters (markdown / code-fence smuggling).
        Regex("(?i)#{1,3}\\s+new instructions"),
        Regex("(?i)BEGIN (?:NEW |OVERRIDE )?INSTRUCTIONS"),
        // Encoded-payload heuristics (base64 of "ignore previous" etc).
        Regex("aWdub3JlIHByZXZpb3Vz"),  // "ignore previous"
        // Common jailbreak prefixes.
        Regex("(?i)in opposite world,"),
        Regex("(?i)hypothetically, if you were"),
    )

    fun scan(s: String): Result {
        if (s.isEmpty()) return Result(false, emptyList())
        val hits = mutableListOf<String>()
        for (p in patterns) {
            p.find(s)?.let { hits.add(it.value) }
        }
        return Result(hits.isNotEmpty(), hits)
    }
}
