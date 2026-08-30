package com.fusion.firewall.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
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

private enum class Filter { ALL, MALICIOUS, SUSPICIOUS, TRACKER, BLOCKED }

@Composable
fun TrafficScreen(viewModel: FusionViewModel, modifier: Modifier = Modifier) {
    val events by viewModel.events.collectAsState()
    val assessments by viewModel.assessments.collectAsState()
    val intel by viewModel.intel.collectAsState()
    val apps by viewModel.apps.collectAsState()
    var filter by remember { mutableStateOf(Filter.ALL) }

    val blockedPkgs = remember(apps) { apps.filter { it.policy == Policy.BLOCK }.map { it.packageName }.toSet() }
    val shown = when (filter) {
        Filter.ALL -> events
        Filter.MALICIOUS -> events.filter { assessments[it.id]?.verdict == Verdict.MALICIOUS }
        Filter.SUSPICIOUS -> events.filter { assessments[it.id]?.verdict == Verdict.SUSPICIOUS }
        Filter.TRACKER -> events.filter { it.flagged }
        Filter.BLOCKED -> events.filter { it.packageName in blockedPkgs }
    }

    Column(modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Text(
            "Live traffic",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
        )
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
                "Nothing here yet. Fusion monitors the apps you BLOCK: turn on protection, " +
                    "block an app in the Apps tab, and its connection attempts appear here — " +
                    "auto-classified as safe, suspicious, tracker or malicious.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                modifier = Modifier.padding(top = 24.dp),
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 12.dp),
            ) {
                items(shown, key = { it.timestamp.toString() + it.id }) { ev ->
                    ConnectionRow(
                        event = ev,
                        assessedText = assessments[ev.id]?.let { it.verdict to it.confidence },
                        assessmentReason = assessments[ev.id]?.reason,
                        intel = intel[ev.remoteIp],
                        onAssess = {
                            viewModel.assess(ev)
                            viewModel.lookupIntel(ev.remoteIp, ev.hostname)
                        },
                        onAllow = { ev.packageName?.let { viewModel.setPolicy(it, Policy.ALLOW) } },
                        onBlock = { ev.packageName?.let { viewModel.setPolicy(it, Policy.BLOCK) } },
                    )
                }
            }
        }
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun ConnectionRow(
    event: ConnectionEvent,
    assessedText: Pair<com.fusion.firewall.ai.Verdict, Float>?,
    assessmentReason: String?,
    intel: com.fusion.firewall.data.model.IpIntel?,
    onAssess: () -> Unit,
    onAllow: () -> Unit,
    onBlock: () -> Unit,
) {
    Card {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    event.appLabel ?: event.packageName ?: "Unknown",
                    fontWeight = FontWeight.SemiBold,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(timeFmt.format(Date(event.timestamp)), style = MaterialTheme.typography.labelSmall)
            }
            Text(
                "${event.hostname ?: event.remoteIp}:${event.remotePort}",
                style = MaterialTheme.typography.bodyMedium,
                color = if (event.flagged) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
            Text(
                "${event.transport} · local :${event.localPort}" +
                    if (event.flagged) " · ${event.flagReason}" else "",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
            if (assessedText != null) {
                Row(Modifier.padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    VerdictBadge(assessedText.first, assessedText.second)
                }
                assessmentReason?.let {
                    Text(it, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 2.dp))
                }
            }
            IntelLine(intel)
            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = onAssess, label = { Text("Ask BinaryCore") })
                AssistChip(onClick = onAllow, label = { Text("Allow app") })
                AssistChip(onClick = onBlock, label = { Text("Block app") })
            }
        }
    }
}
