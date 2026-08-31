package com.fusion.firewall.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.data.model.AppRule
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.PolicySelector
import com.fusion.firewall.ui.formatBytes

@Composable
fun AppsScreen(viewModel: FusionViewModel, modifier: Modifier = Modifier) {
    val apps by viewModel.apps.collectAsState()
    var query by remember { mutableStateOf("") }

    val filtered = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter {
            it.label.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
        }
    }

    Column(modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Text(
            "Apps & services",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
        )
        Row(
            Modifier.fillMaxWidth().padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(
                onClick = { viewModel.blockAllApps() },
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.weight(1f),
            ) { Text("Block all apps") }
            OutlinedButton(
                onClick = { viewModel.unblockAllApps() },
                modifier = Modifier.weight(1f),
            ) { Text("Unblock all") }
        }
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("Search apps") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 12.dp),
        ) {
            items(filtered, key = { it.packageName }) { app ->
                AppRow(app, viewModel)
            }
        }
    }
}

@Composable
private fun AppRow(app: AppRule, viewModel: FusionViewModel) {
    val usage = viewModel.usageFor(app.uid)
    Card {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.padding(end = 8.dp)) {
                    Text(app.label, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyLarge)
                    Text(
                        app.packageName + if (app.system) " · system" else "",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    )
                }
                if (usage != null && usage.total > 0) {
                    Text(
                        formatBytes(usage.total),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
            PolicySelector(
                current = app.policy,
                onSelect = { viewModel.setPolicy(app.packageName, it) },
                modifier = Modifier.padding(top = 10.dp),
            )
        }
    }
}
