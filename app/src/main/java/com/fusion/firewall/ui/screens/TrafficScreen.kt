package com.fusion.firewall.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.ai.Verdict
import com.fusion.firewall.data.model.ConnectionEvent
import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.net.AppCategorizer
import com.fusion.firewall.net.TrafficCategorizer
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.SectionHeader
import com.fusion.firewall.ui.VerdictBadge
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private enum class Filter { ALL, BLOCKED, ALLOWED, MALICIOUS, SUSPICIOUS }

@Composable
fun TrafficScreen(
    viewModel: FusionViewModel,
    modifier: Modifier = Modifier,
    onEnableProtection: () -> Unit = {},
) {
    val events by viewModel.events.collectAsState()
    val assessments by viewModel.assessments.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val blockedPkgs by viewModel.blockedPackages.collectAsState()
    val custom by viewModel.customBlocked.collectAsState()
    val whitelist by viewModel.whitelist.collectAsState()
    val actionStatus by viewModel.actionStatus.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val apps by viewModel.apps.collectAsState()
    var filter by remember { mutableStateOf(Filter.ALL) }
    var showCats by remember { mutableStateOf(false) }
    var showTypes by remember { mutableStateOf(false) }

    val catGroups = remember(apps) {
        apps.groupBy { AppCategorizer.categoryOf(it.packageName, it.label, it.system) }
            .map { it.key to it.value.size }
            .sortedByDescending { it.second }
    }
    val vendorGroups = remember(apps) {
        apps.groupBy { AppCategorizer.vendorOf(it.packageName) }
            .map { it.key to it.value.size }
            .sortedByDescending { it.second }
            .take(12)
    }
    // Traffic-type groups: distinct observed domains classified into families.
    val typeGroups = remember(events) {
        events.mapNotNull { it.hostname }.filter { it.isNotBlank() }.distinct()
            .groupingBy { TrafficCategorizer.classify(it) }.eachCount()
            .toList()
            .sortedByDescending { it.second }
    }

    // Effective, live block state of a row (reflects custom blocks / app blocks /
    // whitelist immediately, not just the historical result).
    fun blockedNow(ev: com.fusion.firewall.data.model.ConnectionEvent): Boolean {
        val host = ev.hostname
        if (host != null && host in whitelist) return false
        return !ev.allowed ||
            (ev.packageName != null && ev.packageName in blockedPkgs) ||
            (host != null && host in custom)
    }

    val shown = when (filter) {
        Filter.ALL -> events
        Filter.BLOCKED -> events.filter { blockedNow(it) }
        Filter.ALLOWED -> events.filter { !blockedNow(it) }
        Filter.MALICIOUS -> events.filter { assessments[it.id]?.verdict == Verdict.MALICIOUS }
        Filter.SUSPICIOUS -> events.filter { assessments[it.id]?.verdict == Verdict.SUSPICIOUS }
    }

    Column(modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Text(
            "Live DNS traffic",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 16.dp, bottom = 4.dp),
        )
        Text(
            "Blocked ${stats.droppedConnections}  ·  Allowed ${stats.allowed}",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
            modifier = Modifier.padding(bottom = 8.dp),
        )
        FreezeCard(
            frozen = settings.frozen,
            onToggle = { viewModel.setFrozen(it, onNeedStart = onEnableProtection) },
        )
        Row(
            Modifier.fillMaxWidth().padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(
                onClick = { viewModel.blockAllVisible() },
                enabled = shown.isNotEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.weight(1f),
            ) { Text("Block all") }
            OutlinedButton(
                onClick = { viewModel.unblockAllVisible() },
                modifier = Modifier.weight(1f),
            ) { Text("Unblock all") }
        }
        actionStatus?.let { msg ->
            Row(
                Modifier.fillMaxWidth().padding(bottom = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    msg,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { viewModel.clearActionStatus() }) { Text("OK") }
            }
        }
        Row(
            Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Filter.entries.forEach { f ->
                FilterChip(
                    selected = filter == f,
                    onClick = { filter = f },
                    label = { Text(f.name.lowercase().replaceFirstChar { it.uppercase() }) },
                )
            }
            TextButton(onClick = { viewModel.clearLog() }) { Text("Clear") }
        }
        Row(
            Modifier.fillMaxWidth().padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = { showCats = !showCats },
                modifier = Modifier.weight(1f),
            ) { Text(if (showCats) "Hide apps ▲" else "By app category ▾") }
            OutlinedButton(
                onClick = { showTypes = !showTypes },
                modifier = Modifier.weight(1f),
            ) { Text(if (showTypes) "Hide types ▲" else "By traffic type ▾") }
        }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(vertical = 12.dp),
        ) {
            if (showTypes) {
                item {
                    Text(
                        "Block or unblock a whole traffic family at once — advertising, analytics, " +
                            "telemetry, streaming, push and more. Fusion classifies the domains it " +
                            "has actually seen, so counts grow as traffic accrues; blocking adds " +
                            "those domains to your block list.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    )
                }
                item { SectionHeader("Traffic types (by domain)") }
                items(typeGroups, key = { "type:" + it.first.name }) { (type, count) ->
                    GroupRow(type.label, count, "domain(s) seen",
                        onBlock = { viewModel.blockTrafficCategory(type) },
                        onUnblock = { viewModel.unblockTrafficCategory(type) })
                }
            }
            if (showCats) {
                item {
                    Text(
                        "Block or unblock every app in a topic at once — the same rubrics as " +
                            "the Apps tab. Blocking a category sinkholes all DNS from those apps, " +
                            "so their traffic stops appearing below.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    )
                }
                item { SectionHeader("App categories") }
                items(catGroups, key = { "cat:" + it.first.name }) { (cat, count) ->
                    GroupRow(cat.label, count, "app(s)",
                        onBlock = { viewModel.blockCategory(cat) },
                        onUnblock = { viewModel.unblockCategory(cat) })
                }
                item { SectionHeader("By vendor (same-vendor hosts)") }
                items(vendorGroups, key = { "ven:" + it.first }) { (vendor, count) ->
                    GroupRow(vendor, count, "app(s)",
                        onBlock = { viewModel.blockVendor(vendor) },
                        onUnblock = { viewModel.unblockVendor(vendor) })
                }
            }
            if (showCats || showTypes) {
                item { SectionHeader("Live traffic") }
            }
            if (shown.isEmpty()) {
                item {
                    Text(
                        "No DNS lookups captured yet. Turn on protection — every app's domain " +
                            "lookups appear here, and blocked ones are marked and counted.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                        modifier = Modifier.padding(top = 24.dp),
                    )
                }
            } else {
                items(shown, key = { it.timestamp.toString() + it.id }) { ev ->
                    DnsRow(
                        event = ev,
                        blocked = blockedNow(ev),
                        assessedText = assessments[ev.id]?.let { it.verdict to it.confidence },
                        assessmentReason = assessments[ev.id]?.reason,
                        appBlocked = ev.packageName != null && ev.packageName in blockedPkgs,
                        onAssess = { viewModel.assess(ev) },
                        onAskChat = { viewModel.askAboutDomain(ev.hostname, ev.appLabel) },
                        onBlock = { viewModel.blockDomain(ev.hostname) },
                        onUnblock = { ev.hostname?.let { viewModel.unblockDomain(it) } },
                        onBlockApp = { ev.packageName?.let { viewModel.setPolicy(it, Policy.BLOCK) } },
                        onUnblockApp = { ev.packageName?.let { viewModel.setPolicy(it, Policy.ALLOW) } },
                    )
                }
            }
        }
    }
}

@Composable
private fun FreezeCard(frozen: Boolean, onToggle: (Boolean) -> Unit) {
    val accent = if (frozen) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    Card(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    if (frozen) "Traffic frozen" else "Freeze all traffic",
                    fontWeight = FontWeight.SemiBold,
                    color = accent,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    if (frozen)
                        "Kill switch is ON — every incoming and outgoing packet is captured and " +
                            "dropped, so no data is sent or received. Turn off to resume."
                    else
                        "Cut off all network data instantly: routes every connection into Fusion " +
                            "and drops it (no data in or out). Enables protection if it's off.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                )
            }
            Switch(checked = frozen, onCheckedChange = onToggle)
        }
    }
}

@Composable
private fun GroupRow(name: String, count: Int, unit: String, onBlock: () -> Unit, onUnblock: () -> Unit) {
    Card {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(name, fontWeight = FontWeight.SemiBold)
                Text("$count $unit", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
            }
            TextButton(onClick = onBlock) { Text("Block", color = MaterialTheme.colorScheme.error) }
            TextButton(onClick = onUnblock) { Text("Unblock") }
        }
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun DnsRow(
    event: ConnectionEvent,
    blocked: Boolean,
    assessedText: Pair<Verdict, Float>?,
    assessmentReason: String?,
    appBlocked: Boolean,
    onAssess: () -> Unit,
    onAskChat: () -> Unit,
    onBlock: () -> Unit,
    onUnblock: () -> Unit,
    onBlockApp: () -> Unit,
    onUnblockApp: () -> Unit,
) {
    Card {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    event.hostname ?: "(no name)",
                    fontWeight = FontWeight.SemiBold,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f),
                )
                DroppedBadge(blocked = blocked)
            }
            Text(
                "${event.appLabel ?: event.packageName ?: "Unknown"}" +
                    (if (appBlocked) " · app blocked" else "") +
                    " · ${timeFmt.format(Date(event.timestamp))}" +
                    (event.flagReason?.let { " · $it" } ?: ""),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
            )
            if (assessedText != null) {
                Row(Modifier.padding(top = 6.dp)) { VerdictBadge(assessedText.first, assessedText.second) }
                assessmentReason?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 2.dp))
                }
            }
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = onAssess, label = { Text("Ask AI") })
                AssistChip(onClick = onAskChat, label = { Text("Ask chat") })
                if (!blocked) {
                    AssistChip(onClick = onBlock, label = { Text("Block site") })
                } else {
                    AssistChip(onClick = onUnblock, label = { Text("Unblock site") })
                }
                if (appBlocked) {
                    AssistChip(onClick = onUnblockApp, label = { Text("Unblock app") })
                } else {
                    AssistChip(onClick = onBlockApp, label = { Text("Block app") })
                }
            }
        }
    }
}

@Composable
private fun DroppedBadge(blocked: Boolean) {
    val color = if (blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    Surface(color = color.copy(alpha = 0.18f), shape = RoundedCornerShape(8.dp)) {
        Text(
            if (blocked) "BLOCKED" else "ALLOWED",
            color = color,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}
