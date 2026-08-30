package com.fusion.firewall.ai

import com.fusion.firewall.data.FusionSettings
import com.fusion.firewall.data.model.ConnectionEvent
import com.fusion.firewall.data.model.Transport
import com.fusion.firewall.net.HostResolver
import com.fusion.firewall.net.InstalledApp

/** A per-app heuristic threat assessment derived from its observed traffic. */
data class AppThreat(
    val packageName: String,
    val label: String,
    val uid: Int,
    val system: Boolean,
    val score: Int,
    val verdict: Verdict,
    val reasons: List<String>,
    val trackerDomains: List<String>,
    val totalLookups: Int,
    val blockedLookups: Int,
) {
    val dangerous: Boolean get() = verdict == Verdict.MALICIOUS
}

/**
 * Analyzes installed apps by the traffic Fusion has actually observed from them:
 * how many known trackers/telemetry endpoints they contact, how many lookups
 * were already blocked, and BinaryCore's verdict on a sample of destinations.
 * Produces a ranked list of dangerous / suspicious apps with human-readable
 * reasons, and feeds the realtime auto-block.
 */
class AppThreatAnalyzer(
    private val hosts: HostResolver,
    private val binaryCore: BinaryCoreManager,
) {
    suspend fun analyze(
        events: List<ConnectionEvent>,
        installed: List<InstalledApp>,
        settings: FusionSettings,
    ): List<AppThreat> {
        val infoByPkg = installed.associateBy { it.packageName }
        val byApp = events.filter { it.packageName != null }.groupBy { it.packageName!! }
        val result = ArrayList<AppThreat>(byApp.size)

        for ((pkg, evs) in byApp) {
            val info = infoByPkg[pkg]
            val domains = evs.mapNotNull { it.hostname }.filter { it.isNotBlank() }.distinct()
            val trackers = domains.filter { hosts.isKnownTracker(it) }
            val blocked = evs.count { !it.allowed }

            var malicious = 0
            var suspicious = 0
            for (d in domains.take(12)) {
                val assessment = binaryCore.assess(
                    ConnectionContext(
                        appLabel = info?.label ?: pkg,
                        packageName = pkg,
                        isSystemApp = info?.system == true,
                        host = d,
                        ip = "",
                        port = 443,
                        transport = Transport.TCP,
                    ),
                    settings,
                )
                when (assessment.verdict) {
                    Verdict.MALICIOUS -> malicious++
                    Verdict.SUSPICIOUS -> suspicious++
                    else -> {}
                }
            }

            val score = (trackers.size * 8 + malicious * 40 + suspicious * 15 + blocked * 3).coerceAtMost(100)
            val verdict = when {
                score >= 40 -> Verdict.MALICIOUS
                score >= 15 -> Verdict.SUSPICIOUS
                else -> Verdict.SAFE
            }
            val reasons = buildList {
                if (trackers.isNotEmpty())
                    add("Contacts ${trackers.size} tracker/telemetry domain(s): ${trackers.take(3).joinToString(", ")}")
                if (malicious > 0) add("$malicious destination(s) look malicious")
                if (suspicious > 0) add("$suspicious destination(s) look suspicious")
                if (blocked > 0) add("$blocked lookup(s) already blocked by your lists")
                if (isEmpty()) add("No risk signals in observed traffic")
            }

            result += AppThreat(
                packageName = pkg,
                label = info?.label ?: pkg,
                uid = info?.uid ?: evs.first().uid,
                system = info?.system == true,
                score = score,
                verdict = verdict,
                reasons = reasons,
                trackerDomains = trackers.take(6),
                totalLookups = domains.size,
                blockedLookups = blocked,
            )
        }
        result.sortByDescending { it.score }
        return result
    }
}
