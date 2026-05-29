package dev.tetherand.app.threat.root

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * AT-command channel via the MediaTek modem serial node.
 *
 * On MTK builds the dedicated AP-side serial endpoints are:
 *   /dev/ttyMT0       AT commands (RIL)
 *   /dev/ttyMT1       NMEA / GPS sentences
 *   /dev/ttyMT2       PPP / data channel
 *
 * AT command set: standard 3GPP TS 27.007 plus MTK extensions.
 * Useful queries:
 *   AT+CSQ         signal quality
 *   AT+COPS?       current operator
 *   AT+CREG?       network registration state
 *   AT+EMRSS       MTK extension: serving + neighbor cell measurements
 *   AT+ESLP        sleep-mode state
 *
 * Root-gated; returns Result.Dormant when un-rooted.
 */
class AtCommandChannel {

    sealed class Result {
        object Dormant : Result()
        data class Ok(val response: String) : Result()
        data class Failed(val reason: String) : Result()
    }

    fun send(cmd: String, port: String = "/dev/ttyMT0", timeoutMs: Long = 1000): Result {
        if (!RootCheck.isRooted()) return Result.Dormant
        val portFile = File(port)
        if (!portFile.exists()) return Result.Failed("no $port")
        return try {
            FileOutputStream(portFile).use { it.write(("$cmd\r\n").toByteArray()) }
            val deadline = System.currentTimeMillis() + timeoutMs
            val sb = StringBuilder()
            FileInputStream(portFile).use { fis ->
                val buf = ByteArray(256)
                while (System.currentTimeMillis() < deadline) {
                    val n = if (fis.available() > 0) fis.read(buf) else { Thread.sleep(20); continue }
                    if (n <= 0) break
                    sb.append(String(buf, 0, n))
                    if (sb.contains("OK") || sb.contains("ERROR")) break
                }
            }
            Result.Ok(sb.toString().trim())
        } catch (e: IOException) {
            Result.Failed(e.message ?: "io")
        }
    }
}
