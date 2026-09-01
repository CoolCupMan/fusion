package com.fusion.firewall.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.fusion.firewall.FusionApp
import com.fusion.firewall.ai.AppThreat
import com.fusion.firewall.ai.ChatClient
import com.fusion.firewall.ai.ChatMessage
import com.fusion.firewall.ai.ConnectionContext
import com.fusion.firewall.ai.ThreatAssessment
import com.fusion.firewall.ai.Verdict
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
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Aggregated, immutable state the whole UI renders from. */
data class DashboardStats(
    val running: Boolean,
    /** Count of apps permanently blocked (updates instantly from the Apps tab). */
    val blockedApps: Int,
    /** Dropped connection attempts seen while monitoring. */
    val droppedConnections: Long,
    val allowed: Long,
    val pendingApps: Int,
    val flaggedNow: Int,
)

/** A destination an app contacted, enriched with intel and an AI verdict. */
data class DestinationIntel(
    val ip: String,
    val hostname: String?,
    val port: Int,
    val transport: String,
    val intel: com.fusion.firewall.data.model.IpIntel?,
    val assessment: ThreatAssessment?,
)

/** A curated block list the user can one-tap import, with a description. */
data class RecommendedList(val name: String, val url: String, val description: String)

/** The result of "ask AI about this blocked app". */
data class AppIntelReport(
    val packageName: String,
    val label: String,
    val destinations: List<DestinationIntel>,
    val summary: String,
    val loading: Boolean = false,
)

class FusionViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as FusionApp).container
    private val repo = container.repository

    private val installedApps = MutableStateFlow<List<InstalledApp>>(emptyList())
    private val usage = MutableStateFlow<Map<Int, AppUsage>>(emptyMap())

    /** AI verdicts for connections (auto-classified by the service + manual asks). */
    val assessments: StateFlow<Map<String, ThreatAssessment>> = ConnectionLog.verdicts

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
                blockedApps = appList.count { it.policy == Policy.BLOCK },
                droppedConnections = blocked,
                allowed = allowed,
                pendingApps = appList.count { it.policy == Policy.PENDING },
                flaggedNow = ev.count { it.flagged },
            )
        }.stateIn(
            viewModelScope, SharingStarted.WhileSubscribed(5000),
            DashboardStats(false, 0, 0L, 0L, 0, 0)
        )

    /** Apps the user has permanently blocked (for the dashboard and Intel tab). */
    val blockedApps: StateFlow<List<AppRule>> =
        apps.map { list -> list.filter { it.policy == Policy.BLOCK } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** Package names currently blocked — for quick per-row lookups in the UI. */
    val blockedPackages: StateFlow<Set<String>> =
        apps.map { list -> list.filter { it.policy == Policy.BLOCK }.map { it.packageName }.toSet() }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptySet())

    // --- Connection intelligence ---------------------------------------------
    private val _intel = MutableStateFlow<Map<String, com.fusion.firewall.data.model.IpIntel>>(emptyMap())
    val intel: StateFlow<Map<String, com.fusion.firewall.data.model.IpIntel>> = _intel

    private val _appReports = MutableStateFlow<Map<String, AppIntelReport>>(emptyMap())
    val appReports: StateFlow<Map<String, AppIntelReport>> = _appReports

    // --- Installed-app threat analysis ---------------------------------------
    private val _appThreats = MutableStateFlow<List<AppThreat>>(emptyList())
    val appThreats: StateFlow<List<AppThreat>> = _appThreats

    fun analyzeApps() = viewModelScope.launch(Dispatchers.IO) {
        runCatching {
            _appThreats.value = container.threatAnalyzer.analyze(events.value, installedApps.value, settings.value)
        }
    }

    fun setAutoBlockDangerous(v: Boolean) = viewModelScope.launch { repo.setAutoBlockDangerous(v) }

    /**
     * Freeze/unfreeze all traffic (kill switch). Freezing rebuilds the tunnel to
     * capture and drop every packet; if protection is off, [onNeedStart] is
     * invoked so the caller can start the VPN (with consent) first.
     */
    fun setFrozen(v: Boolean, onNeedStart: (() -> Unit)? = null) = viewModelScope.launch {
        repo.setFrozen(v)
        if (v && !running.value) onNeedStart?.invoke()
    }

    // --- General-purpose AI chat ---------------------------------------------
    private val _chatMessages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val chatMessages: StateFlow<List<ChatMessage>> = _chatMessages
    private val _chatBusy = MutableStateFlow(false)
    val chatBusy: StateFlow<Boolean> = _chatBusy

    /** Incremented whenever something requests the chat overlay be opened. */
    private val _openChatRequest = MutableStateFlow(0)
    val openChatRequest: StateFlow<Int> = _openChatRequest
    fun requestOpenChat() { _openChatRequest.value++ }

    fun setChatEndpoint(v: String) = viewModelScope.launch { repo.setChatEndpoint(v) }
    fun setChatApiKey(v: String) = viewModelScope.launch { repo.setChatApiKey(v) }
    fun setChatModel(v: String) = viewModelScope.launch { repo.setChatModel(v) }
    fun setChatProvider(p: com.fusion.firewall.data.ChatProvider) = viewModelScope.launch { repo.setChatProvider(p) }
    fun setOpenaiApiKey(v: String) = viewModelScope.launch { repo.setOpenaiApiKey(v) }
    fun setOpenaiModel(v: String) = viewModelScope.launch { repo.setOpenaiModel(v) }
    fun setGoogleApiKey(v: String) = viewModelScope.launch { repo.setGoogleApiKey(v) }
    fun setGoogleModel(v: String) = viewModelScope.launch { repo.setGoogleModel(v) }
    fun clearChat() { _chatMessages.value = emptyList() }

    fun sendChat(text: String) {
        val msg = text.trim()
        if (msg.isEmpty() || _chatBusy.value) return
        _chatMessages.value = _chatMessages.value + ChatMessage("user", msg)
        _chatBusy.value = true
        val context = buildAppContext()
        viewModelScope.launch {
            val raw = ChatClient.send(_chatMessages.value, settings.value, context)
            val (clean, actions) = com.fusion.firewall.ai.ChatActions.parse(raw)
            _chatMessages.value = _chatMessages.value +
                ChatMessage("assistant", clean.ifBlank { if (actions.isEmpty()) raw else "Done." })
            for (a in actions) {
                val result = runCatching { applyChatAction(a) }.getOrElse { "⚠️ Action failed: ${it.message}" }
                _chatMessages.value = _chatMessages.value + ChatMessage("assistant", result)
            }
            _chatBusy.value = false
        }
    }

    /** Execute an assistant action (block/allow apps, domains, categories, all). */
    private suspend fun applyChatAction(a: com.fusion.firewall.ai.ChatAction): String {
        val self = selfPkg()
        val t = a.target?.trim().orEmpty()
        return when (a.action.lowercase()) {
            "block_app", "allow_app" -> {
                val policy = if (a.action.equals("block_app", true)) Policy.BLOCK else Policy.ALLOW
                if (t.isBlank()) return "⚠️ No app specified."
                val matches = apps.value.filter {
                    it.packageName != self &&
                        (it.packageName.equals(t, true) || it.label.contains(t, true) || it.packageName.contains(t, true))
                }
                if (matches.isEmpty()) "⚠️ No installed app matched \"$t\"."
                else {
                    repo.setPolicies(matches.associate { it.packageName to policy })
                    (if (policy == Policy.BLOCK) "⛔ Blocked " else "✅ Allowed ") +
                        matches.take(6).joinToString(", ") { it.label } +
                        (if (matches.size > 6) " +${matches.size - 6} more" else "")
                }
            }
            "block_domain" ->
                if (t.isBlank()) "⚠️ No domain specified." else { container.blockLists.addCustom(t); "⛔ Blocked domain $t" }
            "unblock_domain", "allow_domain" ->
                if (t.isBlank()) "⚠️ No domain specified."
                else { container.blockLists.addWhitelist(t); container.blockLists.removeCustom(t); "✅ Unblocked domain $t" }
            "block_category", "unblock_category" -> {
                val cat = com.fusion.firewall.net.AppCategory.entries.firstOrNull {
                    it.label.contains(t, true) || it.name.replace("_", " ").contains(t, true)
                } ?: return "⚠️ No category matched \"$t\"."
                val policy = if (a.action.startsWith("block")) Policy.BLOCK else Policy.ALLOW
                val matches = apps.value.filter {
                    it.packageName != self &&
                        com.fusion.firewall.net.AppCategorizer.categoryOf(it.packageName, it.label, it.system) == cat
                }
                if (matches.isEmpty()) "No apps found in ${cat.label}."
                else {
                    repo.setPolicies(matches.associate { it.packageName to policy })
                    (if (policy == Policy.BLOCK) "⛔ Blocked " else "✅ Allowed ") + "${matches.size} apps in ${cat.label}."
                }
            }
            "block_all_apps" -> {
                val u = apps.value.filter { it.packageName != self }.associate { it.packageName to Policy.BLOCK }
                repo.setPolicies(u); "⛔ Blocked all apps (${u.size})."
            }
            "unblock_all_apps" -> {
                val u = apps.value.filter { it.packageName != self }.associate { it.packageName to Policy.ALLOW }
                repo.setPolicies(u); "✅ Allowed all apps (${u.size})."
            }
            else -> "⚠️ Unknown action \"${a.action}\"."
        }
    }

    /** A compact live snapshot of the app so the assistant can answer by deduction. */
    private fun buildAppContext(): String {
        val s = settings.value
        val st = stats.value
        val blocked = blockedApps.value
        val lists = blockLists.value
        val custom = customBlocked.value
        val white = whitelist.value
        val ev = events.value
        val recentBlocked = ev.filter { !it.allowed }.mapNotNull { it.hostname }.distinct().take(25)
        val recentAllowed = ev.filter { it.allowed }.mapNotNull { it.hostname }.distinct().take(15)
        val dangerous = appThreats.value.filter { it.verdict != Verdict.SAFE }.take(12)
        return buildString {
            appendLine("Protection: ${if (running.value) "ON" else "OFF"}; default policy for unconfirmed apps: ${s.defaultPolicy}")
            appendLine("Counts: dropped=${st.droppedConnections}, allowed=${st.allowed}, blockedApps=${st.blockedApps}, pendingApps=${st.pendingApps}, flaggedNow=${st.flaggedNow}")
            appendLine("Auto-block dangerous apps: ${s.autoBlockDangerous}; AI auto-apply: ${s.aiAutoApply}; BinaryCore mode: ${s.aiMode}")
            if (blocked.isNotEmpty())
                appendLine("Blocked apps (${blocked.size}): " + blocked.take(30).joinToString(", ") { it.label })
            if (lists.isNotEmpty())
                appendLine("Imported block lists: " + lists.joinToString("; ") { "${it.name} [${it.count} domains, ${if (it.enabled) "enabled" else "disabled"}]" })
            appendLine("Custom blocked domains: ${custom.size}" + if (custom.isNotEmpty()) " (e.g. ${custom.take(15).joinToString(", ")})" else "")
            appendLine("Whitelist: ${white.size}" + if (white.isNotEmpty()) " (e.g. ${white.take(15).joinToString(", ")})" else "")
            if (dangerous.isNotEmpty()) {
                appendLine("Flagged apps:")
                dangerous.forEach { t -> appendLine("  - ${t.label} [${t.verdict}, score ${t.score}]: ${t.reasons.joinToString("; ")}") }
            }
            if (recentBlocked.isNotEmpty()) appendLine("Recently blocked domains: " + recentBlocked.joinToString(", "))
            if (recentAllowed.isNotEmpty()) appendLine("Recently allowed domains: " + recentAllowed.joinToString(", "))
            appendLine("Usage-access granted: $usageAccessGranted; chat: ${s.chatProvider.label}/${s.activeChatModel}")
        }
    }

    /** Seed the chat with a question about a specific connection/domain. */
    fun askAboutDomain(domain: String?, app: String?) {
        val d = domain?.takeIf { it.isNotBlank() } ?: return
        requestOpenChat()
        sendChat("What is the connection to \"$d\"" + (app?.let { " from the app $it" } ?: "") +
            " used for, and should I block it?")
    }

    // --- Root / deep monitoring ----------------------------------------------
    private val _rootAvailable = MutableStateFlow<Boolean?>(null)
    val rootAvailable: StateFlow<Boolean?> = _rootAvailable
    private val _rootConnections = MutableStateFlow<List<com.fusion.firewall.root.RootConnection>>(emptyList())
    val rootConnections: StateFlow<List<com.fusion.firewall.root.RootConnection>> = _rootConnections
    private val _systemServices = MutableStateFlow<List<String>>(emptyList())
    val systemServices: StateFlow<List<String>> = _systemServices

    val usageAccessGranted: Boolean get() = container.usageStats.hasUsageAccess()

    init {
        refreshApps()
        refreshSnapshots()
        viewModelScope.launch {
            while (true) {
                runCatching { refreshUsage() }
                analyzeApps()
                delay(15_000)
            }
        }
    }

    fun refreshApps() = viewModelScope.launch(Dispatchers.IO) {
        runCatching { installedApps.value = container.appInfo.loadAll() }
    }

    private suspend fun refreshUsage() = withContext(Dispatchers.IO) {
        val since = System.currentTimeMillis() - 24L * 60 * 60 * 1000
        usage.value = container.usageStats.usageSince(since)
    }

    fun usageFor(uid: Int): AppUsage? = usage.value[uid]

    fun setPolicy(pkg: String, policy: Policy) = viewModelScope.launch {
        repo.setPolicy(pkg, policy)
    }

    /** Block every installed app (except Fusion itself). */
    fun blockAllApps() = viewModelScope.launch {
        val self = getApplication<android.app.Application>().packageName
        val updates = apps.value.filter { it.packageName != self }.associate { it.packageName to Policy.BLOCK }
        if (updates.isNotEmpty()) repo.setPolicies(updates)
    }

    /** Allow every installed app (clears all app blocks). */
    fun unblockAllApps() = viewModelScope.launch {
        val self = getApplication<android.app.Application>().packageName
        val updates = apps.value.filter { it.packageName != self }.associate { it.packageName to Policy.ALLOW }
        if (updates.isNotEmpty()) repo.setPolicies(updates)
    }

    private fun selfPkg() = getApplication<android.app.Application>().packageName

    fun blockCategory(cat: com.fusion.firewall.net.AppCategory) =
        setCategory(cat, Policy.BLOCK)
    fun unblockCategory(cat: com.fusion.firewall.net.AppCategory) =
        setCategory(cat, Policy.ALLOW)

    private fun setCategory(cat: com.fusion.firewall.net.AppCategory, policy: Policy) = viewModelScope.launch {
        val self = selfPkg()
        val updates = apps.value.filter {
            it.packageName != self &&
                com.fusion.firewall.net.AppCategorizer.categoryOf(it.packageName, it.label, it.system) == cat
        }.associate { it.packageName to policy }
        if (updates.isNotEmpty()) repo.setPolicies(updates)
    }

    fun blockVendor(vendor: String) = setVendor(vendor, Policy.BLOCK)
    fun unblockVendor(vendor: String) = setVendor(vendor, Policy.ALLOW)

    private fun setVendor(vendor: String, policy: Policy) = viewModelScope.launch {
        val self = selfPkg()
        val updates = apps.value.filter {
            it.packageName != self && com.fusion.firewall.net.AppCategorizer.vendorOf(it.packageName) == vendor
        }.associate { it.packageName to policy }
        if (updates.isNotEmpty()) repo.setPolicies(updates)
    }

    /**
     * Block every observed domain classified as a given traffic type (ads,
     * analytics, telemetry, streaming, …). Adds them to the custom block list so
     * lookups to them are sinkholed. Only domains Fusion has actually seen can be
     * classified, so let traffic accrue first for the fullest effect.
     */
    fun blockTrafficCategory(cat: com.fusion.firewall.net.TrafficCategory) = viewModelScope.launch {
        val domains = trafficDomainsOf(cat)
        if (domains.isEmpty()) {
            _actionStatus.value = "No ${cat.label} domains seen yet."
        } else {
            container.blockLists.addCustomAll(domains)
            _actionStatus.value = "Blocked ${domains.size} ${cat.label} domain(s)."
        }
    }

    /** Unblock (whitelist + drop custom) every observed domain of a traffic type. */
    fun unblockTrafficCategory(cat: com.fusion.firewall.net.TrafficCategory) = viewModelScope.launch {
        val domains = trafficDomainsOf(cat)
        if (domains.isEmpty()) {
            _actionStatus.value = "No ${cat.label} domains seen yet."
        } else {
            domains.forEach { container.blockLists.addWhitelist(it); container.blockLists.removeCustom(it) }
            _actionStatus.value = "Unblocked ${domains.size} ${cat.label} domain(s)."
        }
    }

    private fun trafficDomainsOf(cat: com.fusion.firewall.net.TrafficCategory): Set<String> =
        events.value.mapNotNull { it.hostname }.filter { it.isNotBlank() }
            .filter { com.fusion.firewall.net.TrafficCategorizer.classify(it) == cat }
            .toSet()

    fun setDefaultPolicy(policy: Policy) = viewModelScope.launch { repo.setDefaultPolicy(policy) }
    fun setPromptOnNewApps(v: Boolean) = viewModelScope.launch { repo.setPromptOnNewApps(v) }
    fun setBlockPending(v: Boolean) = viewModelScope.launch { repo.setBlockPending(v) }
    fun setAiMode(m: AiMode) = viewModelScope.launch { repo.setAiMode(m) }
    fun setAiAutoApply(v: Boolean) = viewModelScope.launch { repo.setAiAutoApply(v) }
    fun setEndpoint(v: String) = viewModelScope.launch { repo.setBinaryCoreEndpoint(v) }
    fun setApiKey(v: String) = viewModelScope.launch { repo.setBinaryCoreApiKey(v) }
    fun setIpIntelEndpoint(v: String) = viewModelScope.launch { repo.setIpIntelEndpoint(v) }
    fun setIpIntelApiKey(v: String) = viewModelScope.launch { repo.setIpIntelApiKey(v) }
    fun setOnlineIntel(v: Boolean) = viewModelScope.launch { repo.setOnlineIntel(v) }
    fun setRootMode(v: Boolean) = viewModelScope.launch { repo.setRootMode(v) }

    fun clearLog() = ConnectionLog.clear()

    // --- Storage manager: save/load "sets of instructions" -------------------
    private val _snapshots = MutableStateFlow<List<com.fusion.firewall.data.SnapshotMeta>>(emptyList())
    val snapshots: StateFlow<List<com.fusion.firewall.data.SnapshotMeta>> = _snapshots

    private val _storageStatus = MutableStateFlow<String?>(null)
    val storageStatus: StateFlow<String?> = _storageStatus
    fun clearStorageStatus() { _storageStatus.value = null }

    fun refreshSnapshots() = viewModelScope.launch {
        runCatching { _snapshots.value = container.snapshots.list() }
    }

    /** Save the current blocked/unblocked apps & traffic to storage + phone storage. */
    fun saveSnapshot() = viewModelScope.launch {
        val snap = buildSnapshot()
        container.snapshots.saveInternal(snap)
        val path = container.snapshots.exportToPhoneStorage(snap)
        refreshSnapshots()
        _storageStatus.value = if (path != null)
            "Saved. On this phone at: $path — open with any file manager."
        else "Saved to app storage. Couldn't write to shared storage."
    }

    /** Reload the most recent saved set of instructions. */
    fun loadLastSnapshot() = viewModelScope.launch {
        val snap = container.snapshots.latest()
        if (snap == null) { _storageStatus.value = "No saved snapshots yet."; return@launch }
        applySnapshot(snap)
        _storageStatus.value = "Loaded last snapshot (${dateOf(snap.savedAt)}). Rules & lists restored."
    }

    fun loadSnapshot(fileName: String) = viewModelScope.launch {
        val snap = container.snapshots.load(fileName)
        if (snap == null) { _storageStatus.value = "Couldn't read that snapshot."; return@launch }
        applySnapshot(snap)
        _storageStatus.value = "Loaded snapshot from ${dateOf(snap.savedAt)}. Rules & lists restored."
    }

    fun deleteSnapshot(fileName: String) = viewModelScope.launch {
        container.snapshots.delete(fileName)
        refreshSnapshots()
        _storageStatus.value = "Snapshot deleted."
    }

    /** Import a snapshot the user picked from a file manager, then load it. */
    fun importSnapshot(uri: android.net.Uri) = viewModelScope.launch {
        val snap = container.snapshots.readUri(uri)
        if (snap == null) { _storageStatus.value = "That file isn't a Fusion snapshot."; return@launch }
        container.snapshots.saveInternal(snap)
        applySnapshot(snap)
        refreshSnapshots()
        _storageStatus.value = "Imported & loaded snapshot from ${dateOf(snap.savedAt)}."
    }

    private fun buildSnapshot(): com.fusion.firewall.data.FusionSnapshot {
        val appList = apps.value
        val custom = customBlocked.value
        val white = whitelist.value
        val bp = blockedPackages.value
        val ev = events.value
        fun blocked(e: ConnectionEvent): Boolean {
            val h = e.hostname
            if (h != null && h in white) return false
            return !e.allowed || (e.packageName != null && e.packageName in bp) || (h != null && h in custom)
        }
        return com.fusion.firewall.data.FusionSnapshot(
            savedAt = System.currentTimeMillis(),
            appVersion = com.fusion.firewall.BuildConfig.VERSION_NAME,
            blockedApps = appList.filter { it.policy == Policy.BLOCK }.map { it.packageName },
            allowedApps = appList.filter { it.policy == Policy.ALLOW }.map { it.packageName },
            customBlockedDomains = custom.toList(),
            whitelistDomains = white.toList(),
            importedLists = blockLists.value,
            trafficBlocked = ev.filter { blocked(it) }.mapNotNull { it.hostname }.filter { it.isNotBlank() }.distinct(),
            trafficAllowed = ev.filter { !blocked(it) }.mapNotNull { it.hostname }.filter { it.isNotBlank() }.distinct(),
            droppedCount = stats.value.droppedConnections,
            allowedCount = stats.value.allowed,
        )
    }

    private suspend fun applySnapshot(s: com.fusion.firewall.data.FusionSnapshot) {
        val map = HashMap<String, Policy>()
        s.allowedApps.forEach { map[it] = Policy.ALLOW }
        s.blockedApps.forEach { map[it] = Policy.BLOCK }
        repo.replaceAll(map)
        container.blockLists.replaceCustom((s.customBlockedDomains + s.trafficBlocked).toSet())
        container.blockLists.replaceWhitelist(s.whitelistDomains.toSet())
    }

    private fun dateOf(t: Long): String =
        java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US).format(java.util.Date(t))

    private val _actionStatus = MutableStateFlow<String?>(null)
    val actionStatus: StateFlow<String?> = _actionStatus
    fun clearActionStatus() { _actionStatus.value = null }

    /** Block every domain currently visible in the traffic log (adds them all). */
    fun blockAllVisible() = viewModelScope.launch {
        val domains = events.value.mapNotNull { it.hostname }.filter { it.isNotBlank() }.toSet()
        if (domains.isEmpty()) {
            _actionStatus.value = "No domains to block yet."
        } else {
            container.blockLists.addCustomAll(domains)
            _actionStatus.value = "Blocked ${domains.size} domain(s). Lookups to them are now dropped."
        }
    }

    /** Undo all manual blocking: clear custom blocked domains and re-allow blocked apps. */
    fun unblockAllVisible() = viewModelScope.launch {
        val hadApps = blockedApps.value.size
        container.blockLists.clearCustom()
        val allowAll = blockedApps.value.associate { it.packageName to Policy.ALLOW }
        if (allowAll.isNotEmpty()) repo.setPolicies(allowAll)
        _actionStatus.value = "Cleared custom blocks and re-allowed $hadApps app(s)."
    }

    // --- Block lists / whitelist ---------------------------------------------
    val blockLists: StateFlow<List<com.fusion.firewall.data.BlockListMeta>> =
        container.blockLists.lists.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val customBlocked: StateFlow<Set<String>> =
        container.blockLists.custom.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptySet())
    val whitelist: StateFlow<Set<String>> =
        container.blockLists.whitelist.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptySet())

    private val _importStatus = MutableStateFlow<String?>(null)
    val importStatus: StateFlow<String?> = _importStatus

    /** Curated lists the user can import with one tap (downloaded on demand). */
    val recommendedLists: List<RecommendedList> = listOf(
        RecommendedList(
            "StevenBlack (ads + malware)",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "The popular unified hosts file: consolidates reputable sources to block ads, trackers and malware. A great all-round default.",
        ),
        RecommendedList(
            "HaGeZi Pro",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
            "Balanced pro list blocking ads, affiliate/tracking, metrics and known malicious hosts with low breakage.",
        ),
        RecommendedList(
            "OISD Small",
            "https://small.oisd.nl/",
            "Ads and trackers with a strong focus on avoiding false positives — safe for everyday use.",
        ),
        RecommendedList(
            "1Hosts (Lite)",
            "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt",
            "A lightweight, balanced ad/tracker list that rarely breaks sites.",
        ),
        RecommendedList(
            "AdGuard DNS filter",
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "AdGuard's own DNS filter targeting ads and trackers across apps and sites.",
        ),
        RecommendedList(
            "Peter Lowe (ad/tracking)",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
            "Long-maintained list of ad and tracking servers.",
        ),
        RecommendedList(
            "URLhaus (malware)",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            "abuse.ch feed of hosts actively distributing malware. Security-focused; pairs well with an ad list.",
        ),
    )

    /**
     * Curated "whole website category" blacklists. Each is a public, community-
     * maintained hosts list; importing one enables it as an active block list so
     * every matching site is sinkholed for all apps. The first entry blocks
     * publicly-reachable pornography/adult sites.
     */
    val websiteBlacklists: List<RecommendedList> = listOf(
        RecommendedList(
            "All porn / adult sites",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
            "Blocks publicly-reachable pornography and adult websites — a large, community-" +
                "maintained hosts list of known adult domains (tens of thousands of sites). " +
                "Enable it and every app is stopped from resolving those domains.",
        ),
        RecommendedList(
            "Gambling & betting sites",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
            "Online casinos, betting and gambling websites.",
        ),
        RecommendedList(
            "Drugs",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
            "Sites selling or promoting recreational drugs.",
        ),
        RecommendedList(
            "Piracy & torrent sites",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt",
            "Torrent trackers and piracy/warez sites.",
        ),
        RecommendedList(
            "Scam & fraud sites",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
            "Known scam, fraud and deceptive websites.",
        ),
        RecommendedList(
            "Facebook & Instagram",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/facebook.txt",
            "Facebook and Instagram domains — blocks the sites and their embeds/trackers.",
        ),
        RecommendedList(
            "TikTok",
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/tiktok.txt",
            "TikTok domains across apps and the web.",
        ),
    )

    fun activeBlockedDomainCount(): Int = container.domainBlocker.blockedDomainCount

    /** Searchable, embedded catalog of well-known block lists. */
    val listCatalog: List<com.fusion.firewall.data.CatalogList> = com.fusion.firewall.data.ListCatalog.entries

    fun searchCatalog(query: String): List<com.fusion.firewall.data.CatalogList> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return listCatalog
        return listCatalog.filter {
            it.name.lowercase().contains(q) ||
                it.category.lowercase().contains(q) ||
                it.description.lowercase().contains(q) ||
                it.format.lowercase().contains(q)
        }
    }

    /** Block a single domain instantly (adds to the custom list). */
    fun blockDomain(domain: String?) {
        val d = domain?.trim().orEmpty()
        if (d.isEmpty()) return
        viewModelScope.launch { container.blockLists.addCustom(d) }
    }

    /** Unblock a domain: whitelist it (wins over any list) and drop any custom entry. */
    fun unblockDomain(domain: String) = viewModelScope.launch {
        container.blockLists.addWhitelist(domain)
        container.blockLists.removeCustom(domain)
    }

    fun removeWhitelist(domain: String) = viewModelScope.launch { container.blockLists.removeWhitelist(domain) }
    fun addWhitelist(domain: String) = viewModelScope.launch { container.blockLists.addWhitelist(domain.trim()) }
    fun removeCustom(domain: String) = viewModelScope.launch { container.blockLists.removeCustom(domain) }
    fun setListEnabled(id: String, enabled: Boolean) = viewModelScope.launch { container.blockLists.setEnabled(id, enabled) }
    fun removeList(id: String) = viewModelScope.launch { container.blockLists.removeList(id) }

    fun importFromUrl(name: String, url: String) = viewModelScope.launch {
        _importStatus.value = "Downloading ${name.ifBlank { url }}…"
        val result = withContext(Dispatchers.IO) {
            runCatching { com.fusion.firewall.net.BlockListImporter.fromUrl(url) }
        }
        val domains = result.getOrNull()
        when {
            domains == null -> _importStatus.value = "Import failed: ${result.exceptionOrNull()?.message}"
            domains.isEmpty() -> _importStatus.value = "No domains found in the list."
            else -> {
                container.blockLists.importList(name.ifBlank { url }, url, domains)
                _importStatus.value = "Imported ${domains.size} domains."
            }
        }
    }

    fun importFromText(name: String, text: String) = viewModelScope.launch {
        val domains = withContext(Dispatchers.IO) { com.fusion.firewall.net.BlockListImporter.parse(text) }
        if (domains.isEmpty()) { _importStatus.value = "No valid domains found."; return@launch }
        container.blockLists.importList(name.ifBlank { "Pasted list" }, "manual", domains)
        _importStatus.value = "Imported ${domains.size} domains."
    }

    fun clearImportStatus() { _importStatus.value = null }

    /** How many apps would be blocked by [blockAllFlagged], given current data. */
    fun flaggedAppCount(): Int = flaggedAppPackages().size

    private fun flaggedAppPackages(): Set<String> {
        val verdicts = ConnectionLog.verdicts.value
        return events.value.filter { ev ->
            ev.flagged ||
                verdicts[ev.id]?.recommendedPolicy == Policy.BLOCK ||
                verdicts[ev.id]?.verdict == Verdict.MALICIOUS ||
                verdicts[ev.id]?.verdict == Verdict.SUSPICIOUS
        }.mapNotNull { it.packageName }.toSet()
    }

    /** Auto-block every app that hit the block list or a malicious/suspicious verdict. */
    fun blockAllFlagged() = viewModelScope.launch {
        val updates = flaggedAppPackages().associateWith { Policy.BLOCK }
        if (updates.isNotEmpty()) repo.setPolicies(updates)
    }

    /** Fetch geo/entity/ASN intelligence for a destination IP and cache it. */
    fun lookupIntel(ip: String, host: String?) = viewModelScope.launch {
        if (_intel.value.containsKey(ip)) return@launch
        val result = container.ipIntel.lookup(ip, host, settings.value)
        _intel.value = _intel.value + (ip to result)
    }

    /**
     * "Ask AI about this blocked app": gather every destination it has contacted
     * (from live history and, if available, the root connection table), enrich
     * each with intel + a BinaryCore verdict, and summarize.
     */
    fun askAiAboutApp(app: AppRule) = viewModelScope.launch(Dispatchers.IO) {
        _appReports.value = _appReports.value +
            (app.packageName to AppIntelReport(app.packageName, app.label, emptyList(), "Analyzing…", loading = true))

        val current = settings.value
        // Destinations from observed traffic.
        val fromEvents = events.value.filter { it.packageName == app.packageName }
            .map { Triple(it.remoteIp, it.hostname, it.remotePort) to it.transport.name }
        // Destinations from the kernel table (root), matched by uid.
        val fromRoot = _rootConnections.value.filter { it.uid == app.uid }
            .map { Triple(it.remoteAddress, null as String?, it.remotePort) to it.protocol.uppercase() }
        val distinct = (fromEvents + fromRoot).distinctBy { it.first }.take(25)

        val destinations = distinct.map { (key, proto) ->
            val (ip, host, port) = key
            val intel = runCatching { container.ipIntel.lookup(ip, host, current) }.getOrNull()
            val assessment = runCatching {
                container.binaryCore.assess(
                    ConnectionContext(
                        appLabel = app.label,
                        packageName = app.packageName,
                        isSystemApp = app.system,
                        host = intel?.hostname ?: host,
                        ip = ip,
                        port = port,
                        transport = com.fusion.firewall.data.model.Transport.entries
                            .firstOrNull { it.name == proto } ?: com.fusion.firewall.data.model.Transport.TCP,
                    ),
                    current,
                )
            }.getOrNull()
            DestinationIntel(ip, intel?.hostname ?: host, port, proto, intel, assessment)
        }

        val risky = destinations.count {
            it.assessment?.recommendedPolicy == Policy.BLOCK
        }
        val countries = destinations.mapNotNull { it.intel?.country }.distinct()
        val vendors = destinations.mapNotNull { it.intel?.org }.distinct().take(4)
        val summary = when {
            destinations.isEmpty() ->
                "No destinations observed yet for ${app.label}. Enable monitoring or root mode, " +
                    "then let it run so Fusion can attribute its connections."
            else -> buildString {
                append("${app.label} contacted ${destinations.size} distinct endpoint(s). ")
                if (risky > 0) append("$risky look risky (BinaryCore recommends blocking). ")
                if (vendors.isNotEmpty()) append("Vendors: ${vendors.joinToString(", ")}. ")
                if (countries.isNotEmpty()) append("Regions: ${countries.joinToString(", ")}.")
            }
        }
        _appReports.value = _appReports.value +
            (app.packageName to AppIntelReport(app.packageName, app.label, destinations, summary))
    }

    // --- Root / deep monitoring ----------------------------------------------
    fun refreshRoot() = viewModelScope.launch(Dispatchers.IO) {
        val available = container.root.isRootAvailable()
        _rootAvailable.value = available
        if (available) {
            _rootConnections.value = container.root.connections()
            _systemServices.value = container.root.services()
        }
    }

    fun appLabelForUid(uid: Int): String =
        container.appInfo.appForUid(uid)?.label ?: "uid $uid"

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
        ConnectionLog.recordAssessment(event.id, result)
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
