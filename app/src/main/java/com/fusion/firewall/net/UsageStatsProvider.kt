package com.fusion.firewall.net

import android.app.AppOpsManager
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.os.RemoteException

data class AppUsage(val uid: Int, val rxBytes: Long, val txBytes: Long) {
    val total: Long get() = rxBytes + txBytes
}

/**
 * Per-app data usage via [NetworkStatsManager]. Requires the PACKAGE_USAGE_STATS
 * special access; when it is not granted the app shows realtime connection data
 * only and prompts the user to grant it.
 */
class UsageStatsProvider(private val context: Context) {

    fun hasUsageAccess(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** Total mobile+wifi usage per uid since [since] (epoch millis). */
    fun usageSince(since: Long): Map<Int, AppUsage> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return emptyMap()
        if (!hasUsageAccess()) return emptyMap()
        val nsm = context.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager
            ?: return emptyMap()
        val now = System.currentTimeMillis()
        val out = HashMap<Int, AppUsage>()
        for (transport in intArrayOf(
            NetworkCapabilities.TRANSPORT_WIFI,
            NetworkCapabilities.TRANSPORT_CELLULAR
        )) {
            accumulate(nsm, transport, since, now, out)
        }
        return out
    }

    private fun accumulate(
        nsm: NetworkStatsManager,
        transport: Int,
        since: Long,
        now: Long,
        out: HashMap<Int, AppUsage>,
    ) {
        try {
            nsm.querySummary(transport, null, since, now).use { stats ->
                val bucket = android.app.usage.NetworkStats.Bucket()
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(bucket)
                    val existing = out[bucket.uid]
                    out[bucket.uid] = AppUsage(
                        uid = bucket.uid,
                        rxBytes = (existing?.rxBytes ?: 0) + bucket.rxBytes,
                        txBytes = (existing?.txBytes ?: 0) + bucket.txBytes,
                    )
                }
            }
        } catch (_: RemoteException) {
        } catch (_: SecurityException) {
        } catch (_: Exception) {
            // Some OEM builds (e.g. certain MediaTek ROMs) throw unchecked
            // exceptions from querySummary; treat as "no usage data".
        }
    }
}
