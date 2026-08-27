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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
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
) {
    val stats by viewModel.stats.collectAsState()
    val events by viewModel.events.collectAsState()

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
            StatCard("Blocked", stats.blocked.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            StatCard("Pending apps", stats.pendingApps.toString(), MaterialTheme.colorScheme.secondary, Modifier.weight(1f))
            StatCard("Flagged", stats.flaggedNow.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
        }

        Button(onClick = { viewModel.autoTriageAll() }, modifier = Modifier.fillMaxWidth()) {
            Text("Auto-triage pending apps with BinaryCore")
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
