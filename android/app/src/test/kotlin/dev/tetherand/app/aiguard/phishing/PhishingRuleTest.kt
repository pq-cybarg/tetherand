package dev.tetherand.app.aiguard.phishing

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PhishingRuleTest {

    @Test fun classic_urgency_phish_flagged_high() {
        val v = PhishingRule.classify(
            "URGENT: Your account will be suspended in 24 hours. " +
            "Verify now at http://paypa1-secure.tk/login or lose access."
        )
        assertEquals(PhishingRule.Verdict.High, v.verdict)
        assertTrue(v.reasons.isNotEmpty())
    }

    @Test fun benign_text_passes() {
        val v = PhishingRule.classify("Hey can you grab milk on the way home? Thanks <3")
        assertEquals(PhishingRule.Verdict.Low, v.verdict)
    }

    @Test fun typo_squat_domain_alone_flags_medium() {
        // arnazon.com instead of amazon.com — Levenshtein 1, IDN-style swap.
        val v = PhishingRule.classify("see your order: https://arnazon-orders.com/track/389")
        assertTrue(v.verdict == PhishingRule.Verdict.Medium || v.verdict == PhishingRule.Verdict.High)
    }
}
