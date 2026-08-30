package com.fusion.firewall.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.fusion.firewall.ui.screens.AiScreen
import com.fusion.firewall.ui.screens.AppsScreen
import com.fusion.firewall.ui.screens.DashboardScreen
import com.fusion.firewall.ui.screens.IntelScreen
import com.fusion.firewall.ui.screens.SettingsScreen
import com.fusion.firewall.ui.screens.TrafficScreen

private enum class Tab(val label: String, val icon: ImageVector) {
    DASHBOARD("Dashboard", Icons.Filled.Dashboard),
    TRAFFIC("Traffic", Icons.Filled.Timeline),
    APPS("Apps", Icons.Filled.Apps),
    AI("BinaryCore", Icons.Filled.AutoAwesome),
    INTEL("Intel", Icons.Filled.Public),
    SETTINGS("Settings", Icons.Filled.Settings),
}

@Composable
fun FusionRoot(
    viewModel: FusionViewModel,
    onToggleFirewall: (Boolean) -> Unit,
    onOpenUsageAccessSettings: () -> Unit,
) {
    var tab by remember { mutableStateOf(Tab.DASHBOARD) }

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { entry ->
                    NavigationBarItem(
                        selected = tab == entry,
                        onClick = { tab = entry },
                        icon = { Icon(entry.icon, contentDescription = entry.label) },
                        label = { Text(entry.label) },
                    )
                }
            }
        }
    ) { padding ->
        val content = Modifier.padding(padding)
        when (tab) {
            Tab.DASHBOARD -> DashboardScreen(viewModel, onToggleFirewall, content) { tab = Tab.TRAFFIC }
            Tab.TRAFFIC -> TrafficScreen(viewModel, content)
            Tab.APPS -> AppsScreen(viewModel, content)
            Tab.AI -> AiScreen(viewModel, content)
            Tab.INTEL -> IntelScreen(viewModel, content)
            Tab.SETTINGS -> SettingsScreen(viewModel, onOpenUsageAccessSettings, content)
        }
    }
}
