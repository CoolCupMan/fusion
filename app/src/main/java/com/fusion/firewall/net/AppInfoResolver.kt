package com.fusion.firewall.net

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Process
import java.util.concurrent.ConcurrentHashMap

/** Metadata about an installed application relevant to the firewall. */
data class InstalledApp(
    val packageName: String,
    val uid: Int,
    val label: String,
    val system: Boolean,
    val hasInternet: Boolean,
)

/**
 * Resolves package/uid/label information and caches it. Enumerates every app
 * that holds the INTERNET permission (the set the firewall can act on) and
 * provides fast uid -> app lookups for the packet loop.
 */
class AppInfoResolver(private val pm: PackageManager) {

    private val byUid = ConcurrentHashMap<Int, InstalledApp>()
    private val labelCache = ConcurrentHashMap<String, String>()

    fun loadAll(): List<InstalledApp> {
        val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        val result = ArrayList<InstalledApp>(packages.size)
        for (info in packages) {
            val hasInternet = pm.checkPermission(
                "android.permission.INTERNET", info.packageName
            ) == PackageManager.PERMISSION_GRANTED
            if (!hasInternet) continue
            val app = InstalledApp(
                packageName = info.packageName,
                uid = info.uid,
                label = label(info),
                system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                hasInternet = true,
            )
            byUid[app.uid] = app
            result.add(app)
        }
        result.sortBy { it.label.lowercase() }
        return result
    }

    fun appForUid(uid: Int): InstalledApp? {
        byUid[uid]?.let { return it }
        // Fall back to the platform mapping for uids not yet cached.
        val names = pm.getPackagesForUid(uid) ?: return specialUid(uid)
        val pkg = names.firstOrNull() ?: return specialUid(uid)
        return runCatching {
            val info = pm.getApplicationInfo(pkg, 0)
            InstalledApp(pkg, uid, label(info), (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0, true)
                .also { byUid[uid] = it }
        }.getOrElse { specialUid(uid) }
    }

    private fun specialUid(uid: Int): InstalledApp? = when (uid) {
        Process.myUid() -> InstalledApp("com.fusion.firewall", uid, "Fusion", false, true)
        0 -> InstalledApp("android.root", 0, "System (root)", true, true)
        else -> null
    }

    fun icon(packageName: String): Drawable? =
        runCatching { pm.getApplicationIcon(packageName) }.getOrNull()

    private fun label(info: ApplicationInfo): String =
        labelCache.getOrPut(info.packageName) { pm.getApplicationLabel(info).toString() }
}
