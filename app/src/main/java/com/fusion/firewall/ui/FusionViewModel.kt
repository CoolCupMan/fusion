package com.fusion.firewall.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.fusion.firewall.FusionApp
import com.fusion.firewall.ai.ConnectionContext
import com.fusion.firewall.ai.ThreatAssessment
import com.fusion.firewall.data.AiMode
import com.fusion.firewall.data.ConnectionLog
import com.fusion.firewall.data.FusionSettings
import com.fusion.firewall.data.model.AppRule
import com.fusion.firewall.data.model.ConnectionEvent
import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.net.AppUsage
import com.fusion.firewall.net.InstalledApp
import com.fusion.firewall.vpn.FusionVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Aggregated, immutable state the whole UI renders from. */
data class DashboardStats(
    val running: Boolean,
    val blocked: Long,
    val allowed: Long,
    val pendingApps: Int,
    val flaggedNow: Int,
)

class FusionViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as FusionApp).container
    private val repo = container.repository

    private val installedApps = MutableStateFlow<List<InstalledApp>>(emptyList())
    private val usage = MutableStateFlow<Map<Int, AppUsage>>(emptyMap())
    private val _assessments = MutableStateFlow<Map<String, ThreatAssessment>>(emptyMap())
    val assessments: StateFlow<Map<String, ThreatAssessment>> = _assessments

    val settings: StateFlow<FusionSettings> = repo.settings
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), FusionSettings())

    val events: StateFlow<List<ConnectionEvent>> = ConnectionLog.events
    val running: StateFlow<Boolean> = FusionVpnService.running

    /** Every internet-capable app with its current explicit rule (or PENDING). */
    val apps: StateFlow<List<AppRule>> =
        combine(installedApps, repo.rules, usage) { apps, rules, usageMap ->
            apps.map { info ->
                AppRule(
                    packageName = info.packageName,
                    uid = info.uid,
                    label = info.label,
                    policy = rules[info.packageName] ?: Policy.PENDING,
                    system = info.system,
                )
            }.sortedWith(
                compareByDescending<AppRule> { (usageMap[it.uid]?.total ?: 0L) }
                    .thenBy { it.label.lowercase() }
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val stats: StateFlow<DashboardStats> =
        combine(
            running,
            ConnectionLog.blockedCount,
            ConnectionLog.allowedCount,
            apps,
            events,
        ) { run, blocked, allowed, appList, ev ->
            DashboardStats(
                running = run,
                blocked = blocked,
                allowed = allowed,
                pendingApps = appList.count { it.policy == Policy.PENDING },
                flaggedNow = ev.count { it.flagged },
            )
        }.stateIn(
            viewModelScope, SharingStarted.WhileSubscribed(5000),
            DashboardStats(false, 0, 0, 0, 0)
        )

    val usageAccessGranted: Boolean get() = container.usageStats.hasUsageAccess()

    init {
        refreshApps()
        viewModelScope.launch {
            while (true) {
                refreshUsage()
                delay(15_000)
            }
        }
    }

    fun refreshApps() = viewModelScope.launch(Dispatchers.IO) {
        installedApps.value = container.appInfo.loadAll()
    }

    private suspend fun refreshUsage() = withContext(Dispatchers.IO) {
        val since = System.currentTimeMillis() - 24L * 60 * 60 * 1000
        usage.value = container.usageStats.usageSince(since)
    }

    fun usageFor(uid: Int): AppUsage? = usage.value[uid]

    fun setPolicy(pkg: String, policy: Policy) = viewModelScope.launch {
        repo.setPolicy(pkg, policy)
    }

    fun setDefaultPolicy(policy: Policy) = viewModelScope.launch { repo.setDefaultPolicy(policy) }
    fun setPromptOnNewApps(v: Boolean) = viewModelScope.launch { repo.setPromptOnNewApps(v) }
    fun setBlockPending(v: Boolean) = viewModelScope.launch { repo.setBlockPending(v) }
    fun setAiMode(m: AiMode) = viewModelScope.launch { repo.setAiMode(m) }
    fun setAiAutoApply(v: Boolean) = viewModelScope.launch { repo.setAiAutoApply(v) }
    fun setEndpoint(v: String) = viewModelScope.launch { repo.setBinaryCoreEndpoint(v) }
    fun setApiKey(v: String) = viewModelScope.launch { repo.setBinaryCoreApiKey(v) }

    fun clearLog() = ConnectionLog.clear()

    /** Ask BinaryCore about a live connection and cache the verdict for the UI. */
    fun assess(event: ConnectionEvent) = viewModelScope.launch {
        val info = event.uid.takeIf { it > 0 }?.let { container.appInfo.appForUid(it) }
        val ctx = ConnectionContext(
            appLabel = event.appLabel ?: (event.packageName ?: "unknown"),
            packageName = event.packageName ?: "unknown",
            isSystemApp = info?.system == true,
            host = event.hostname,
            ip = event.remoteIp,
            port = event.remotePort,
            transport = event.transport,
        )
        val result = container.binaryCore.assess(ctx, settings.value)
        _assessments.value = _assessments.value + (event.id to result)
    }

    /** Apply BinaryCore's recommendation for every pending app at once. */
    fun autoTriageAll() = viewModelScope.launch(Dispatchers.IO) {
        val current = settings.value
        val updates = HashMap<String, Policy>()
        for (app in apps.value.filter { it.policy == Policy.PENDING }) {
            val recentHost = events.value.firstOrNull { it.packageName == app.packageName }
            val ctx = ConnectionContext(
                appLabel = app.label,
                packageName = app.packageName,
                isSystemApp = app.system,
                host = recentHost?.hostname,
                ip = recentHost?.remoteIp ?: "",
                port = recentHost?.remotePort ?: 443,
                transport = recentHost?.transport ?: com.fusion.firewall.data.model.Transport.TCP,
            )
            val result = container.binaryCore.assess(ctx, current)
            if (result.recommendedPolicy != Policy.PENDING) {
                updates[app.packageName] = result.recommendedPolicy
            }
        }
        if (updates.isNotEmpty()) repo.setPolicies(updates)
    }
}
