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
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.VerdictBadge
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private enum class Filter { ALL, BLOCKED, ALLOWED, MALICIOUS, SUSPICIOUS }

@Composable
fun TrafficScreen(viewModel: FusionViewModel, modifier: Modifier = Modifier) {
    val events by viewModel.events.collectAsState()
    val assessments by viewModel.assessments.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val blockedPkgs by viewModel.blockedPackages.collectAsState()
    var filter by remember { mutableStateOf(Filter.ALL) }

    val shown = when (filter) {
        Filter.ALL -> events
        Filter.BLOCKED -> events.filter { !it.allowed }
        Filter.ALLOWED -> events.filter { it.allowed }
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

        if (shown.isEmpty()) {
            Text(
                "No DNS lookups captured yet. Turn on protection — every app's domain " +
                    "lookups appear here, and blocked ones are marked and counted.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                modifier = Modifier.padding(top = 24.dp),
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(vertical = 12.dp),
            ) {
                items(shown, key = { it.timestamp.toString() + it.id }) { ev ->
                    DnsRow(
                        event = ev,
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

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun DnsRow(
    event: ConnectionEvent,
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
                DroppedBadge(blocked = !event.allowed)
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
                if (event.allowed) {
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
