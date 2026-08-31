package com.fusion.firewall.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.fusion.firewall.ui.screens.AppsScreen
import com.fusion.firewall.ui.screens.ChatScreen
import com.fusion.firewall.ui.screens.DashboardScreen
import com.fusion.firewall.ui.screens.IntelScreen
import com.fusion.firewall.ui.screens.ListsScreen
import com.fusion.firewall.ui.screens.SettingsScreen
import com.fusion.firewall.ui.screens.StatsScreen
import com.fusion.firewall.ui.screens.TrafficScreen

private enum class Tab(val label: String, val icon: ImageVector) {
    DASHBOARD("Dashboard", Icons.Filled.Dashboard),
    TRAFFIC("Traffic", Icons.Filled.Timeline),
    APPS("Apps", Icons.Filled.Apps),
    LISTS("Lists", Icons.Filled.Block),
    INTEL("Threats", Icons.Filled.Security),
    SETTINGS("Settings", Icons.Filled.Settings),
}

@Composable
fun FusionRoot(
    viewModel: FusionViewModel,
    onToggleFirewall: (Boolean) -> Unit,
    onOpenUsageAccessSettings: () -> Unit,
) {
    var tab by remember { mutableStateOf(Tab.DASHBOARD) }
    var showChat by remember { mutableStateOf(false) }
    var showStats by remember { mutableStateOf(false) }

    // Open the chat overlay whenever an "Ask chat" action requests it.
    val openChatRequest by viewModel.openChatRequest.collectAsState()
    LaunchedEffect(openChatRequest) {
        if (openChatRequest > 0) showChat = true
    }

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
        },
        floatingActionButton = {
            if (!showChat) {
                FloatingActionButton(onClick = { showChat = true }) {
                    Icon(Icons.AutoMirrored.Filled.Chat, contentDescription = "AI chat")
                }
            }
        },
    ) { padding ->
        val content = Modifier.padding(padding)
        if (showChat) {
            ChatScreen(viewModel, onClose = { showChat = false }, modifier = content)
            return@Scaffold
        }
        if (showStats) {
            StatsScreen(viewModel, onClose = { showStats = false }, modifier = content)
            return@Scaffold
        }
        when (tab) {
            Tab.DASHBOARD -> DashboardScreen(
                viewModel, onToggleFirewall, content,
                onSeeTraffic = { tab = Tab.TRAFFIC },
                onOpenStats = { showStats = true },
            )
            Tab.TRAFFIC -> TrafficScreen(
                viewModel, content,
                onEnableProtection = { onToggleFirewall(true) },
            )
            Tab.APPS -> AppsScreen(viewModel, content)
            Tab.LISTS -> ListsScreen(viewModel, content)
            Tab.INTEL -> IntelScreen(viewModel, content)
            Tab.SETTINGS -> SettingsScreen(viewModel, onOpenUsageAccessSettings, content)
        }
    }
}
