package dev.tetherand.app.aiguard.voiceprint

import android.content.Context

/**
 * State machine for the spec's "verify caller" Signal-handshake.
 *
 * Steps:
 *   IDLE → CALL_ACTIVE → CHALLENGE_SENT → WAITING_RESPONSE
 *        → VERIFIED                                        (success path)
 *        → REJECTED                                        (mismatch)
 *
 * The spec leaves the actual challenge open — common choices: a
 * pre-shared "safe word", a question whose answer only the trusted
 * contact knows ("what bar did we go to in 2019?"), a Signal-Voice
 * out-of-band SAS, or a YubiKey touch. v1 implements the local
 * "user-confirmed safe-word" path: the user types the response, the
 * system compares against the stored hash, and toggles VERIFIED/REJECTED.
 *
 * The voiceprint corroboration adds an extra signal once voiceguard-v1
 * is loaded (M10.x).
 */
class VerifyCallerFlow(
    private val ctx: Context,
    private val phoneE164: String,
) {
    enum class State { Idle, CallActive, ChallengeSent, WaitingResponse, Verified, Rejected }
    var state: State = State.Idle
        private set

    fun onCallActive() { state = State.CallActive }

    fun issueChallenge(): String {
        state = State.ChallengeSent
        // A safeword challenge string for the UI to surface. The user
        // reads this aloud and the trusted contact responds with the
        // pre-agreed correct word.
        return "Speak the agreed safe-word for ${phoneE164.takeLast(4)}."
    }

    fun submitResponse(typedResponse: String, expectedHash: String): State {
        val h = java.security.MessageDigest.getInstance("SHA-256")
            .digest(typedResponse.trim().lowercase().toByteArray())
            .joinToString("") { "%02x".format(it) }
        state = if (h == expectedHash) State.Verified else State.Rejected
        return state
    }
}
