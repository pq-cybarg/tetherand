package dev.tetherand.app.hardened

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dev.tetherand.app.threat.collector.AppAudit
import org.json.JSONArray
import org.json.JSONObject

/**
 * Pre/Post-conference attestation snapshot. Captures the device
 * fingerprint + package signatures + system settings + threat-baseline
 * at toggle time so the user can diff and spot tampering after DEFCON.
 *
 * Spec mapping: maps directly to the spec's "Pre / Post Conference
 * Attestation" table.
 */
object AttestationSnapshot {

    fun capture(ctx: Context): String {
        val out = JSONObject()
        out.put("ts_ms", System.currentTimeMillis())

        // 1. Build fingerprint.
        out.put("build", JSONObject().apply {
            put("fingerprint", Build.FINGERPRINT)
            put("bootloader", Build.BOOTLOADER)
            put("baseband", Build.getRadioVersion() ?: "")
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("android_version", Build.VERSION.RELEASE)
            put("sdk_int", Build.VERSION.SDK_INT)
            put("security_patch", Build.VERSION.SECURITY_PATCH)
            put("hardware", Build.HARDWARE)
        })

        // 2. Package signing certs + versions per app.
        val pm = ctx.packageManager
        val packages = JSONArray()
        for (info in pm.getInstalledPackages(PackageManager.GET_SIGNATURES or PackageManager.GET_PERMISSIONS)) {
            packages.put(JSONObject().apply {
                put("pkg", info.packageName)
                put("version_code", info.longVersionCode)
                put("version_name", info.versionName ?: "")
                put("sig_hash", info.signatureHashHex())
            })
        }
        out.put("packages", packages)

        // 3. Device admins, accessibility services (M7a's AppAudit).
        val appSnap = AppAudit.snapshot(ctx)
        out.put("device_admins", JSONArray(appSnap.deviceAdmins.toList()))
        out.put("accessibility_services", JSONArray(appSnap.accessibilityServices.toList()))

        // 4. Root CA store names (system + user).
        val systemCerts = try {
            java.io.File("/system/etc/security/cacerts").list()?.toList() ?: emptyList()
        } catch (_: Throwable) { emptyList() }
        out.put("ca_system", JSONArray(systemCerts))
        val userCerts = try {
            val ks = java.security.KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            ks.aliases().toList()
        } catch (_: Throwable) { emptyList<String>() }
        out.put("ca_user", JSONArray(userCerts))

        return out.toString(2)
    }

    /** Diff two snapshots, return a JSONObject of changes. */
    fun diff(before: String, after: String): JSONObject {
        val a = JSONObject(before)
        val b = JSONObject(after)
        val out = JSONObject()
        out.put("ts_before", a.optLong("ts_ms"))
        out.put("ts_after", b.optLong("ts_ms"))
        out.put("build_changed", a.optJSONObject("build")?.toString() != b.optJSONObject("build")?.toString())

        fun toMap(arr: JSONArray): Map<String, String> {
            val m = mutableMapOf<String, String>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                m[o.getString("pkg")] = "${o.getLong("version_code")}/${o.optString("sig_hash")}"
            }
            return m
        }
        val pa = toMap(a.getJSONArray("packages"))
        val pb = toMap(b.getJSONArray("packages"))
        val newPkgs = pb.keys - pa.keys
        val removedPkgs = pa.keys - pb.keys
        val sigChanged = pa.keys.intersect(pb.keys).filter { pa[it] != pb[it] }
        out.put("new_packages", JSONArray(newPkgs.toList()))
        out.put("removed_packages", JSONArray(removedPkgs.toList()))
        out.put("changed_packages", JSONArray(sigChanged))

        fun stringSet(j: JSONObject, key: String): Set<String> =
            (0 until j.getJSONArray(key).length())
                .map { j.getJSONArray(key).getString(it) }.toSet()
        val newAdmins = stringSet(b, "device_admins") - stringSet(a, "device_admins")
        val newAcc = stringSet(b, "accessibility_services") - stringSet(a, "accessibility_services")
        val newUserCa = stringSet(b, "ca_user") - stringSet(a, "ca_user")
        out.put("new_device_admins", JSONArray(newAdmins.toList()))
        out.put("new_accessibility_services", JSONArray(newAcc.toList()))
        out.put("new_user_ca", JSONArray(newUserCa.toList()))
        return out
    }

    private fun PackageInfo.signatureHashHex(): String {
        @Suppress("DEPRECATION")
        val sig = (signatures ?: signingInfo?.apkContentsSigners)?.firstOrNull() ?: return ""
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
