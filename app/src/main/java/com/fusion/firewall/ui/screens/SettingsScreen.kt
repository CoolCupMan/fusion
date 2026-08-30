package com.fusion.firewall.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.fusion.firewall.BuildConfig
import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.PolicySelector
import com.fusion.firewall.ui.SectionHeader

@Composable
fun SettingsScreen(
    viewModel: FusionViewModel,
    onOpenUsageAccessSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val settings by viewModel.settings.collectAsState()
    var endpoint by remember(settings.binaryCoreEndpoint) { mutableStateOf(settings.binaryCoreEndpoint) }
    var apiKey by remember(settings.binaryCoreApiKey) { mutableStateOf(settings.binaryCoreApiKey) }
    var intelEndpoint by remember(settings.ipIntelEndpoint) { mutableStateOf(settings.ipIntelEndpoint) }
    var intelKey by remember(settings.ipIntelApiKey) { mutableStateOf(settings.ipIntelApiKey) }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)

        SectionHeader("Default for unconfirmed apps")
        Text(
            "Applied to any app you have not personally decided on yet.",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
        )
        PolicySelector(current = settings.defaultPolicy, onSelect = { viewModel.setDefaultPolicy(it) })

        ToggleRow(
            title = "Prompt on new apps",
            subtitle = "Notify me the first time an unconfirmed app connects.",
            checked = settings.promptOnNewApps,
            onChange = { viewModel.setPromptOnNewApps(it) },
        )
        ToggleRow(
            title = "Block pending traffic",
            subtitle = "Capture and drop traffic from apps awaiting a decision.",
            checked = settings.blockPendingByDefault,
            onChange = { viewModel.setBlockPending(it) },
        )

        SectionHeader("BinaryCore API")
        OutlinedTextField(
            value = endpoint,
            onValueChange = { endpoint = it; viewModel.setEndpoint(it) },
            label = { Text("Endpoint URL") },
            placeholder = { Text("https://…/assess") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = apiKey,
            onValueChange = { apiKey = it; viewModel.setApiKey(it) },
            label = { Text("API key") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )

        SectionHeader("Connection intelligence")
        Text(
            "Endpoint that maps an IP to geo/entity/ASN data (ipinfo-style JSON). " +
                "Used to show where blocked apps' traffic goes. Location is approximate.",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
        )
        OutlinedTextField(
            value = intelEndpoint,
            onValueChange = { intelEndpoint = it; viewModel.setIpIntelEndpoint(it) },
            label = { Text("IP intelligence endpoint") },
            placeholder = { Text("https://…/{ip}") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = intelKey,
            onValueChange = { intelKey = it; viewModel.setIpIntelApiKey(it) },
            label = { Text("Intelligence API key") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        ToggleRow(
            title = "Enable online lookups",
            subtitle = "Sends destination IPs to the endpoint above for enrichment.",
            checked = settings.onlineIntelEnabled,
            onChange = { viewModel.setOnlineIntel(it) },
        )

        SectionHeader("Deep monitoring (root)")
        ToggleRow(
            title = "Root mode",
            subtitle = "If this device is already rooted, read the kernel connection table, " +
                "processes and services directly. Fusion never roots or flashes the device.",
            checked = settings.rootModeEnabled,
            onChange = { viewModel.setRootMode(it) },
        )

        SectionHeader("Permissions")
        Card {
            Column(Modifier.fillMaxWidth().padding(14.dp)) {
                Text(
                    if (viewModel.usageAccessGranted) "Usage access granted"
                    else "Usage access not granted",
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    "Needed to show per-app data usage totals.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
                )
                OutlinedButton(
                    onClick = onOpenUsageAccessSettings,
                    modifier = Modifier.padding(top = 8.dp),
                ) { Text("Open usage access settings") }
            }
        }

        SectionHeader("About")
        Text(
            "Fusion ${BuildConfig.VERSION_NAME}\nApp ID: ${BuildConfig.APPLICATION_ID}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
        )
        Text(
            "Fusion enforces policy through a local VPN. It does not send your " +
                "traffic anywhere; captured packets are inspected on-device and dropped.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f),
        )
    }
}

@Composable
private fun ToggleRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Card {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 8.dp)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
                )
            }
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}
