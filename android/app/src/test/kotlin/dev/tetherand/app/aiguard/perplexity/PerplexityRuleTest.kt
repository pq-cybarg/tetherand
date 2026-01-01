package dev.tetherand.app.aiguard.perplexity

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PerplexityRuleTest {

    @Test fun scores_human_text_lower_than_ai_text() {
        // A short human-written DEFCON warning — quirky, idiomatic.
        val human = "yo heads up — saw a fake AT&T tent on the floor today, " +
                    "they tried to scan badges. ngl looked legit at first."
        // A clean, formulaic LLM-style response.
        val llm = "Thank you for your message. I want to ensure that we " +
                  "address your concerns effectively. Please provide additional " +
                  "details so that we can assist you further. We appreciate " +
                  "your patience and understanding."
        val rh = PerplexityRule.score(human)
        val rl = PerplexityRule.score(llm)
        assertTrue(rl.aiLikelihood > rh.aiLikelihood,
            "Expected LLM text to score higher AI-likelihood: human=${rh.aiLikelihood} llm=${rl.aiLikelihood}")
    }

    @Test fun handles_empty_input_gracefully() {
        val r = PerplexityRule.score("")
        assertTrue(r.aiLikelihood in 0.0..1.0)
    }

    @Test fun handles_single_word() {
        val r = PerplexityRule.score("hello")
        assertTrue(r.aiLikelihood in 0.0..1.0)
    }
}
