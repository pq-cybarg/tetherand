package dev.tetherand.app.aiguard.osint

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

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
 */
object OsintExposureProbe {

    data class PasswordResult(val pwned: Boolean, val occurrences: Long)
    data class BreachesResult(val ok: Boolean, val breaches: List<String>, val err: String?)

    /** k-anonymity pwned-passwords check. */
    fun isPasswordPwned(password: String): PasswordResult {
        val sha1 = MessageDigest.getInstance("SHA-1").digest(password.toByteArray())
            .joinToString("") { "%02X".format(it) }
        val prefix = sha1.take(5)
        val suffix = sha1.drop(5)
        val url = URL("https://api.pwnedpasswords.com/range/$prefix")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("User-Agent", "Tetherand-AI-Guard/1")
            val reader = BufferedReader(InputStreamReader(conn.inputStream))
            for (line in reader.lineSequence()) {
                val parts = line.trim().split(':')
                if (parts.size >= 2 && parts[0].equals(suffix, ignoreCase = true)) {
                    return PasswordResult(true, parts[1].toLongOrNull() ?: 0L)
                }
            }
            return PasswordResult(false, 0L)
        } catch (t: Throwable) {
            return PasswordResult(false, 0L)
        } finally {
            try { conn.disconnect() } catch (_: Throwable) {}
        }
    }

    /** Account-breaches lookup; key-required. */
    fun emailBreaches(email: String, apiKey: String): BreachesResult {
        if (apiKey.isEmpty()) return BreachesResult(false, emptyList(), "api key required")
        val url = URL("https://haveibeenpwned.com/api/v3/breachedaccount/${java.net.URLEncoder.encode(email, "UTF-8")}?truncateResponse=true")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("User-Agent", "Tetherand-AI-Guard/1")
            conn.setRequestProperty("hibp-api-key", apiKey)
            val code = conn.responseCode
            if (code == 404) return BreachesResult(true, emptyList(), null)
            if (code != 200) return BreachesResult(false, emptyList(), "http $code")
            val body = conn.inputStream.bufferedReader().readText()
            // Lazy JSON: parse [{"Name":"X"},{"Name":"Y"}].
            val names = Regex("\"Name\":\"([^\"]+)\"").findAll(body).map { it.groupValues[1] }.toList()
            return BreachesResult(true, names, null)
        } catch (t: Throwable) {
            return BreachesResult(false, emptyList(), t.message)
        } finally {
            try { conn.disconnect() } catch (_: Throwable) {}
        }
    }
}
