package dev.tetherand.app.aiguard.egress

/**
 * Catalogue of cloud LLM API SNIs. If your phone connects to any of
 * these *without your knowledge* it's either:
 *   - a misbehaving SDK in an app you installed,
 *   - or compromise.
 *
 * Tetherand never connects to any of these — confirmed by integration
 * test on the M3 chain.
 *
 * Update path: in-APK + delta updates through the active Privacy Chain
 * only (M10.x signed-bundle mechanism). Never out-of-band.
 */
object LlmApiWatchlist {

    /** Exact SNIs (host == entry). */
    val EXACT: Set<String> = setOf(
        "api.openai.com",
        "api.anthropic.com",
        "api.cohere.ai",
        "api.cohere.com",
        "api.together.xyz",
        "api.together.ai",
        "api.fireworks.ai",
        "api.deepinfra.com",
        "api.perplexity.ai",
        "api.mistral.ai",
        "api.x.ai",
        "api.groq.com",
        "api.replicate.com",
        "api.runway.com",
        "api.runwayml.com",
        "api.elevenlabs.io",
        "api.deepgram.com",
        "api.assemblyai.com",
    )

    /** Suffix matches (SNI endsWith entry). For wildcard subdomains. */
    val SUFFIX: List<String> = listOf(
        ".openai.azure.com",
        ".cognitiveservices.azure.com",
        ".generativelanguage.googleapis.com",
        ".aiplatform.googleapis.com",          // Vertex AI
        ".us-central1-aiplatform.googleapis.com",
        ".bedrock-runtime.amazonaws.com",      // AWS Bedrock
        ".bedrock.amazonaws.com",
        ".inference.ai.azure.com",
        ".llm.cloudflare.com",
        ".workers.ai.cloudflare.com",
    )
}
