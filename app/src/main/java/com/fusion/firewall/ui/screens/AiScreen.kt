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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.data.AiMode
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.SectionHeader
import com.fusion.firewall.ui.VerdictBadge

@Composable
fun AiScreen(viewModel: FusionViewModel, modifier: Modifier = Modifier) {
    val settings by viewModel.settings.collectAsState()
    val assessments by viewModel.assessments.collectAsState()

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("BinaryCore", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "On-device and API-backed intelligence that recommends whether each " +
                "connection should be permanently allowed or blocked.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
        )

        SectionHeader("Engine")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AiMode.entries.forEach { mode ->
                FilterChip(
                    selected = settings.aiMode == mode,
                    onClick = { viewModel.setAiMode(mode) },
                    label = { Text(mode.name.lowercase().replaceFirstChar { it.uppercase() }) },
                )
            }
        }
        val engineNote = when (settings.aiMode) {
            AiMode.LOCAL -> "Offline heuristic engine. No data leaves the device."
            AiMode.REMOTE -> if (settings.binaryCoreEndpoint.isBlank())
                "No API endpoint set — add one in Settings." else "Using API: ${settings.binaryCoreEndpoint}"
            AiMode.HYBRID -> "Local first, API to confirm low-confidence verdicts."
        }
        Text(engineNote, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)

        Card {
            Row(
                Modifier.fillMaxWidth().padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Auto-apply recommendations", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Let BinaryCore permanently allow/block pending apps automatically.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
                    )
                }
                Switch(checked = settings.aiAutoApply, onCheckedChange = { viewModel.setAiAutoApply(it) })
            }
        }

        Button(onClick = { viewModel.autoTriageAll() }, modifier = Modifier.fillMaxWidth()) {
            Text("Triage all pending apps now")
        }

        SectionHeader("Recent verdicts")
        if (assessments.isEmpty()) {
            Text(
                "No verdicts yet. Tap \"Ask BinaryCore\" on a connection in the Traffic tab.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        } else {
            assessments.values.sortedByDescending { it.confidence }.take(20).forEach { a ->
                Card {
                    Column(Modifier.fillMaxWidth().padding(14.dp)) {
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            VerdictBadge(a.verdict, a.confidence)
                            Text(
                                "→ ${a.recommendedPolicy.name}",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                        Text(a.reason, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
                        Text(
                            a.source,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                        )
                    }
                }
            }
        }
    }
}
