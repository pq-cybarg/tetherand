package dev.tetherand.app.aiguard.fieldguide

/**
 * Static field-guide entries surfaced in the AI tab. These are spec-listed
 * "AI-era attacker tactics" for DEFCON 34 (Aug 2026):
 *   - deepfake-on-call
 *   - fake-AirDrop conference-app
 *   - fake-Reddit-link clickbait
 *   - QR-poison badge stickers
 *   - prompt-injection via shared text
 *   - voice-clone vishing
 *
 * Dynamic entries (the "Conference live threat feed" spec defense) are
 * fetched from a curated list of community feeds through the active
 * Privacy Chain — ship in M10.x once the feed source is finalized.
 */
object ConferenceFieldGuide {

    data class Entry(val title: String, val body: String, val severity: String)

    val STATIC: List<Entry> = listOf(
        Entry("Deepfake-on-call",
              "An attacker may impersonate a trusted voice within seconds of capturing a sample. " +
              "Use the 'verify caller' safe-word handshake before responding to anything urgent.",
              "high"),
        Entry("Fake AirDrop conference-app",
              "Lookalike profiles sharing 'Schedule.pdf' or 'Map.pdf' — refuse all AirDrop / Nearby Share " +
              "from unknown senders. Pull schedule from defcon.org over your chain.",
              "high"),
        Entry("QR-poison badge stickers",
              "Adversarial QR codes pasted over real ones lead to credential-harvest pages. " +
              "Scan through Tetherand's URL preview before tapping. Confirm vendor URLs in person.",
              "medium"),
        Entry("Prompt-injection via shared text",
              "Pasted messages may contain 'ignore previous instructions' scaffolds aimed at any LLM " +
              "agent you copy them into. The clipboard scrubber flags these automatically in Hardened Mode.",
              "medium"),
        Entry("LLM-API exfil from compromised app",
              "Apps may silently send your prompts to api.openai.com / api.anthropic.com / etc. " +
              "Tetherand's EgressLlmApiWatch flags hits — review your DNS log periodically.",
              "high"),
        Entry("Voice-clone vishing on hotel landline",
              "Caller claims to be hotel front desk + reads a 'verification code'. Hang up; call the desk " +
              "from the room number listed on the door, not the inbound number.",
              "high"),
        Entry("Fake firmware-update prompt",
              "Pop-ups that look like Android updates but are crafted overlays. Real updates only appear " +
              "in Settings > System > Software update.",
              "medium"),
        Entry("Adversarial vendor swag",
              "Stickers + pin-back buttons with embedded NFC tags reading user data. Keep NFC off in " +
              "Hardened Mode unless actively using it.",
              "medium"),
    )
}
