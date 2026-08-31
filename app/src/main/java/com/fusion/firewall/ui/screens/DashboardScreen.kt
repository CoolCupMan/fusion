package com.fusion.firewall.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.SectionHeader
import com.fusion.firewall.ui.StatCard

@Composable
fun DashboardScreen(
    viewModel: FusionViewModel,
    onToggleFirewall: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    onSeeTraffic: () -> Unit,
    onOpenStats: () -> Unit = {},
) {
    val stats by viewModel.stats.collectAsState()
    val events by viewModel.events.collectAsState()
    val blockedApps by viewModel.blockedApps.collectAsState()

    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Fusion", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
        Text(
            "Realtime firewall & traffic monitor",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
        )

        Card(
            colors = CardDefaults.cardColors(
                containerColor = if (stats.running)
                    MaterialTheme.colorScheme.primary.copy(alpha = 0.16f)
                else MaterialTheme.colorScheme.surface
            )
        ) {
            Row(
                Modifier.fillMaxWidth().padding(20.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column {
                    Text(
                        if (stats.running) "Protection active" else "Protection off",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = if (stats.running) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        if (stats.running) "Unconfirmed traffic is being captured"
                        else "Turn on to monitor and enforce",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    )
                }
                Switch(checked = stats.running, onCheckedChange = onToggleFirewall)
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Blocked apps", stats.blockedApps.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            StatCard("Pending apps", stats.pendingApps.toString(), MaterialTheme.colorScheme.secondary, Modifier.weight(1f))
            StatCard("Dropped", stats.droppedConnections.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
        }

        var showHelp by remember { mutableStateOf(false) }
        TextButton(onClick = { showHelp = !showHelp }) {
            Text(if (showHelp) "Hide: what do these mean?" else "What does \"Dropped\" mean?")
        }
        if (showHelp) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    HelpRow(
                        "Dropped",
                        "The number of DNS lookups Fusion has blocked (dropped) since you turned " +
                            "protection on. It goes up in realtime whenever an app tries to resolve a " +
                            "domain that is on an enabled block list, one you blocked manually, or that " +
                            "belongs to an app you blocked — Fusion answers \"does not exist\" so the " +
                            "connection never happens. It only counts while protection is ON, and resets " +
                            "when you tap Clear in the Traffic tab. A domain you whitelist is never dropped.",
                        MaterialTheme.colorScheme.primary,
                    )
                    HelpRow(
                        "Blocked apps",
                        "How many apps you have permanently blocked. Every DNS lookup from a blocked " +
                            "app is dropped, so it can't reach the network by name.",
                        MaterialTheme.colorScheme.error,
                    )
                    HelpRow(
                        "Pending apps",
                        "Apps you haven't decided on yet. With the default policy \"Allow\" they stay " +
                            "online; set the default to \"Ask\" (Settings) to review them.",
                        MaterialTheme.colorScheme.secondary,
                    )
                }
            }
        }

        Button(onClick = { viewModel.autoTriageAll() }, modifier = Modifier.fillMaxWidth()) {
            Text("Auto-triage pending apps with BinaryCore")
        }
        OutlinedButton(onClick = onOpenStats, modifier = Modifier.fillMaxWidth()) {
            Text("View stats & charts")
        }

        SectionHeader("Blocked apps (${blockedApps.size})")
        if (blockedApps.isEmpty()) {
            Text(
                "No apps blocked yet. Block one in the Apps tab and it appears here instantly — no monitoring required.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        } else {
            blockedApps.take(6).forEach { app ->
                Card {
                    Row(
                        Modifier.fillMaxWidth().padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(app.label, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Blocked",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }

        SectionHeader("Latest flagged connections")
        val flagged = events.filter { it.flagged }.take(4)
        if (flagged.isEmpty()) {
            Text(
                "No flagged connections yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        } else {
            flagged.forEach { ev ->
                Card {
                    Column(Modifier.padding(14.dp)) {
                        Text(ev.appLabel ?: ev.packageName ?: "Unknown app", fontWeight = FontWeight.SemiBold)
                        Text(
                            "${ev.hostname ?: ev.remoteIp}:${ev.remotePort} · ${ev.transport}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
            OutlinedButton(onClick = onSeeTraffic, modifier = Modifier.fillMaxWidth()) {
                Text("See all traffic")
            }
        }
    }
}

@Composable
private fun HelpRow(title: String, body: String, accent: androidx.compose.ui.graphics.Color) {
    Column {
        Text(title, fontWeight = FontWeight.Bold, color = accent, style = MaterialTheme.typography.titleSmall)
        Text(
            body,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
        )
    }
}
