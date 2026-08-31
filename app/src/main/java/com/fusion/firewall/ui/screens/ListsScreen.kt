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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.SectionHeader

@Composable
fun ListsScreen(viewModel: FusionViewModel, modifier: Modifier = Modifier) {
    val lists by viewModel.blockLists.collectAsState()
    val custom by viewModel.customBlocked.collectAsState()
    val whitelist by viewModel.whitelist.collectAsState()
    val status by viewModel.importStatus.collectAsState()
    val events by viewModel.events.collectAsState()

    var url by remember { mutableStateOf("") }
    var pasted by remember { mutableStateOf("") }
    var whiteEntry by remember { mutableStateOf("") }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Block lists", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "Import domain block lists (hosts files or plain lists). Enabled lists filter " +
                "DNS for every app in realtime — blocked names are sinkholed instantly.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
        )
        status?.let {
            Card {
                Row(
                    Modifier.fillMaxWidth().padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                    TextButton(onClick = { viewModel.clearImportStatus() }) { Text("OK") }
                }
            }
        }

        SectionHeader("Recommended")
        viewModel.recommendedLists.forEach { rl ->
            var expanded by remember { mutableStateOf(false) }
            Card {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(rl.name, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                        TextButton(onClick = { expanded = !expanded }) { Text(if (expanded) "Hide" else "Details") }
                        OutlinedButton(onClick = { viewModel.importFromUrl(rl.name, rl.url) }) { Text("Import") }
                    }
                    if (expanded) {
                        Text(
                            rl.description,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                        Text(
                            rl.url,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f),
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            }
        }

        SectionHeader("Import from URL")
        OutlinedTextField(
            value = url,
            onValueChange = { url = it },
            label = { Text("https://…/hosts") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { viewModel.importFromUrl("", url); url = "" },
            enabled = url.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Download & import") }

        SectionHeader("Paste domains")
        OutlinedTextField(
            value = pasted,
            onValueChange = { pasted = it },
            label = { Text("One domain per line (or hosts format)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { viewModel.importFromText("Pasted list", pasted); pasted = "" },
            enabled = pasted.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Import pasted") }

        SectionHeader("Active lists (${lists.size})")
        if (lists.isEmpty()) {
            Text("No lists yet.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
        } else {
            lists.forEach { meta ->
                Card {
                    Row(
                        Modifier.fillMaxWidth().padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(meta.name, fontWeight = FontWeight.SemiBold)
                            Text("${meta.count} domains · ${meta.source}", style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), maxLines = 2)
                        }
                        Switch(checked = meta.enabled, onCheckedChange = { viewModel.setListEnabled(meta.id, it) })
                        TextButton(onClick = { viewModel.removeList(meta.id) }) { Text("Remove") }
                    }
                }
            }
        }

        SectionHeader("Custom blocked (${custom.size})")
        if (custom.isEmpty()) {
            Text("Block a domain from the Traffic tab to add it here.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
        } else {
            custom.sorted().forEach { domain -> DomainRow(domain, "Unblock") { viewModel.unblockDomain(domain) } }
        }

        SectionHeader("Filtered connections")
        val filtered = remember(events) { events.filter { !it.allowed }.distinctBy { it.hostname }.take(20) }
        if (filtered.isEmpty()) {
            Text(
                "Connections blocked by your lists will show here while protection is on.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        } else {
            filtered.forEach { ev ->
                Card {
                    Column(Modifier.fillMaxWidth().padding(12.dp)) {
                        Text(ev.hostname ?: "(no name)", fontWeight = FontWeight.SemiBold)
                        Text(
                            "${ev.appLabel ?: ev.packageName ?: "Unknown"} · ${ev.flagReason ?: "blocked"}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                        )
                        val whitelisted = ev.hostname != null && ev.hostname in whitelist
                        Row(
                            Modifier.padding(top = 6.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            TextButton(
                                onClick = { ev.hostname?.let { viewModel.unblockDomain(it) } },
                                enabled = !whitelisted,
                            ) { Text(if (whitelisted) "Unblocked ✓" else "Unblock") }
                            TextButton(onClick = { viewModel.askAboutDomain(ev.hostname, ev.appLabel) }) { Text("Ask chat") }
                        }
                    }
                }
            }
        }

        SectionHeader("Whitelist (${whitelist.size})")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = whiteEntry,
                onValueChange = { whiteEntry = it },
                label = { Text("Always allow domain") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(
                onClick = { viewModel.addWhitelist(whiteEntry); whiteEntry = "" },
                enabled = whiteEntry.isNotBlank(),
            ) { Text("Add") }
        }
        whitelist.sorted().forEach { domain -> DomainRow(domain, "Remove") { viewModel.removeWhitelist(domain) } }
    }
}

@Composable
private fun DomainRow(domain: String, action: String, onClick: () -> Unit) {
    Card {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(domain, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = onClick) { Text(action) }
        }
    }
}
