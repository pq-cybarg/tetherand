package dev.tetherand.app.threat.collector

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager

data class AppSnapshot(
    val packages: Map<String, AppEntry>,
    val deviceAdmins: Set<String>,
    val accessibilityServices: Set<String>,
    val tsMs: Long = System.currentTimeMillis(),
)

data class AppEntry(
    val pkg: String,
    val versionCode: Long,
    val grantedDangerous: Set<String>,
)

object AppAudit {
    private val DANGEROUS = setOf(
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
    )

    fun snapshot(ctx: Context): AppSnapshot {
        val pm = ctx.packageManager
        val pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            .associate { it.packageName to it.toEntry() }
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admins = dpm.activeAdmins.orEmpty().map { it.packageName }.toSet()
        val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val accs = am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .map { it.resolveInfo.serviceInfo.packageName }.toSet()
        return AppSnapshot(pkgs, admins, accs)
    }

    private fun PackageInfo.toEntry(): AppEntry {
        val granted = mutableSetOf<String>()
        val perms = requestedPermissions ?: emptyArray()
        val flags = requestedPermissionsFlags ?: IntArray(0)
        for (i in perms.indices) {
            val isGranted = (i < flags.size) && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            if (isGranted && perms[i] in DANGEROUS) granted += perms[i]
        }
        return AppEntry(
            pkg = packageName,
            versionCode = longVersionCode,
            grantedDangerous = granted,
        )
    }
}
