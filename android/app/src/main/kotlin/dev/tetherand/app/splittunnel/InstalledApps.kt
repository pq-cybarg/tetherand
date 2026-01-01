package dev.tetherand.app.splittunnel

import android.content.Context
import android.content.pm.ApplicationInfo

data class InstalledApp(val pkg: String, val label: String, val isSystem: Boolean)

object InstalledApps {
    fun list(ctx: Context, includeSystem: Boolean = false): List<InstalledApp> {
        val pm = ctx.packageManager
        return pm.getInstalledApplications(0)
            .filter { includeSystem || (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
            .map {
                InstalledApp(
                    pkg = it.packageName,
                    label = pm.getApplicationLabel(it).toString(),
                    isSystem = (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                )
            }
            .sortedBy { it.label.lowercase() }
    }
}
