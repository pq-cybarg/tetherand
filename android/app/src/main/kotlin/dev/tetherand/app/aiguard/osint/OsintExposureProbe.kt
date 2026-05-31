package dev.tetherand.app.aiguard.osint

import dev.tetherand.app.crypto.SecureBytes
import dev.tetherand.app.net.PinnedHttp
import okhttp3.Request
import java.security.MessageDigest
import java.util.Arrays

/**
 * OSINT exposure dashboard. Off by default; user opts in from the AI tab.
 *
 * The HIBP password API uses k-anonymity (you send the first 5 chars of
 * the SHA-1 of the password, receive a list of suffixes back), so it
 * leaks no information about the queried password and requires no API
 * key. Safe to call through any Privacy Chain.
 *
 * The HIBP email-breaches API requires an API key (off by default —
 * user supplies their own).
 *
 * IntelligenceX requires a paid key — we expose the call signature but
 * don't ship a free path.
 *
 * **Network posture**: all calls go through {@link PinnedHttp}, which
 * pins the HIBP cert chain at the SubjectPublicKeyInfo level. A
 * compromised root CA cannot inject a substitute cert; the system
 * also enforces the pin via `network_security_config.xml`. Belt and
 * braces.
 *
 * **Memory posture**: the SHA-1 hash bytes are wiped from the heap
 * immediately after the hex conversion. The k-anonymity prefix that
 * actually goes over the wire is non-sensitive (5 hex chars = 20 bits
 * of preimage signal, identical to billions of other passwords).
 */
object OsintExposureProbe {

    data class PasswordResult(val pwned: Boolean, val occurrences: Long)
    data class BreachesResult(val ok: Boolean, val breaches: List<String>, val err: String?)

    /** k-anonymity pwned-passwords check. */
    fun isPasswordPwned(password: String): PasswordResult {
        // Compute SHA-1 over the password bytes. Wipe the byte buffer
        // before it goes out of scope — keeping it on the heap until
        // the next GC sweep is the same as keeping the password.
        val pwBytes = password.toByteArray(Charsets.UTF_8)
        val sha1Bytes = try {
            MessageDigest.getInstance("SHA-1").digest(pwBytes)
        } finally {
            SecureBytes.wipe(pwBytes)
        }
        val sha1Hex = try {
            sha1Bytes.joinToString("") { "%02X".format(it) }
        } finally {
            SecureBytes.wipe(sha1Bytes)
        }
        val prefix = sha1Hex.substring(0, 5)
        val suffix = sha1Hex.substring(5)
        // sha1Hex itself isn't fully secret (only the prefix leaves),
        // but we drop our reference and best-effort wipe to keep the
        // residency window short.
        SecureBytes.bestEffortWipeString(sha1Hex)

        val client = PinnedHttp.client()
        return try {
            val req = Request.Builder()
                .url("https://api.pwnedpasswords.com/range/$prefix")
                .header("User-Agent", "Tetherand-AI-Guard/1")
                .header("Add-Padding", "true")  // HIBP-recommended response padding
                .get()
                .build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use PasswordResult(false, 0L)
                val body = resp.body?.string() ?: return@use PasswordResult(false, 0L)
                for (line in body.lineSequence()) {
                    val parts = line.trim().split(':')
                    if (parts.size >= 2 && parts[0].equals(suffix, ignoreCase = true)) {
                        return@use PasswordResult(true, parts[1].toLongOrNull() ?: 0L)
                    }
                }
                PasswordResult(false, 0L)
            }
        } catch (_: Throwable) {
            PasswordResult(false, 0L)
        } finally {
            // No-op: OkHttp closes the connection per the use {} block.
            // The dispatcher's worker thread will GC the OkHttpClient
            // on its own; nothing for us to do here.
        }
    }

    /** Account-breaches lookup; key-required. */
    fun emailBreaches(email: String, apiKey: String): BreachesResult {
        if (apiKey.isEmpty()) return BreachesResult(false, emptyList(), "api key required")
        val client = PinnedHttp.client()
        return try {
            val req = Request.Builder()
                .url("https://haveibeenpwned.com/api/v3/breachedaccount/${java.net.URLEncoder.encode(email, "UTF-8")}?truncateResponse=true")
                .header("User-Agent", "Tetherand-AI-Guard/1")
                .header("hibp-api-key", apiKey)
                .get()
                .build()
            client.newCall(req).execute().use { resp ->
                val code = resp.code
                if (code == 404) return@use BreachesResult(true, emptyList(), null)
                if (code != 200) return@use BreachesResult(false, emptyList(), "http $code")
                val body = resp.body?.string() ?: return@use BreachesResult(false, emptyList(), "empty body")
                val names = Regex("\"Name\":\"([^\"]+)\"").findAll(body).map { it.groupValues[1] }.toList()
                BreachesResult(true, names, null)
            }
        } catch (t: Throwable) {
            BreachesResult(false, emptyList(), t.message)
        } finally {
            // API key wipe is a no-op here because the caller still
            // holds the String. If the caller wants to wipe, they
            // should call SecureBytes.bestEffortWipeString(apiKey).
            // We don't do it for them because it would invalidate
            // their copy without their consent.
        }
    }
}
