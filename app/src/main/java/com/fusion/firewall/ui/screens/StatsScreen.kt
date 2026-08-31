package com.fusion.firewall.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.data.model.ConnectionEvent
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.SectionHeader
import com.fusion.firewall.ui.StatCard

@Composable
fun StatsScreen(viewModel: FusionViewModel, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val events by viewModel.events.collectAsState()
    val stats by viewModel.stats.collectAsState()

    val blockedEvents = remember(events) { events.filter { !it.allowed } }
    val topDomains = remember(blockedEvents) {
        blockedEvents.mapNotNull { it.hostname }.groupingBy { it }.eachCount()
            .entries.sortedByDescending { it.value }.take(8)
    }
    val topApps = remember(blockedEvents) {
        blockedEvents.groupingBy { it.appLabel ?: it.packageName ?: "Unknown" }.eachCount()
            .entries.sortedByDescending { it.value }.take(8)
    }
    val trackers = remember(events) {
        events.filter { it.flagged }.mapNotNull { it.hostname }.distinct()
    }
    val timeline = remember(events) { buildTimeline(events) }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Stats & charts", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            TextButton(onClick = onClose) { Text("Close") }
        }

        val total = (stats.droppedConnections + stats.allowed).coerceAtLeast(1)
        val rate = (stats.droppedConnections * 100 / total)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard("Blocked", stats.droppedConnections.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
            StatCard("Allowed", stats.allowed.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
            StatCard("Block rate", "$rate%", MaterialTheme.colorScheme.secondary, Modifier.weight(1f))
        }

        SectionHeader("Blocked lookups over time")
        if (timeline.all { it == 0 }) {
            EmptyHint("No blocked lookups captured yet.")
        } else {
            TimeBars(timeline, MaterialTheme.colorScheme.error)
            Text(
                "Recent blocked lookups per minute (older → newer).",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        }

        SectionHeader("Top blocked domains")
        if (topDomains.isEmpty()) EmptyHint("Nothing blocked yet.")
        else {
            val max = topDomains.first().value
            topDomains.forEach { BarRow(it.key, it.value, max, MaterialTheme.colorScheme.error) }
        }

        SectionHeader("Top blocked apps")
        if (topApps.isEmpty()) EmptyHint("Nothing blocked yet.")
        else {
            val max = topApps.first().value
            topApps.forEach { BarRow(it.key, it.value, max, MaterialTheme.colorScheme.secondary) }
        }

        SectionHeader("Trackers seen (${trackers.size})")
        if (trackers.isEmpty()) EmptyHint("No known trackers detected yet.")
        else {
            Card {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    trackers.take(12).forEach {
                        Text(it, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

/** Count of blocked events per minute for the last 24 minute-buckets. */
private fun buildTimeline(events: List<ConnectionEvent>): List<Int> {
    val buckets = 24
    val now = System.currentTimeMillis()
    val counts = IntArray(buckets)
    for (e in events) {
        if (e.allowed) continue
        val minutesAgo = ((now - e.timestamp) / 60_000L).toInt()
        if (minutesAgo in 0 until buckets) counts[buckets - 1 - minutesAgo]++
    }
    return counts.toList()
}

@Composable
private fun TimeBars(values: List<Int>, color: Color) {
    val max = (values.maxOrNull() ?: 0).coerceAtLeast(1)
    Row(
        Modifier.fillMaxWidth().height(110.dp).padding(vertical = 6.dp),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        values.forEach { v ->
            val h = (v.toFloat() / max * 100f).toInt().coerceAtLeast(if (v > 0) 6 else 2)
            Box(
                Modifier
                    .weight(1f)
                    .height(h.dp)
                    .background(
                        if (v > 0) color else color.copy(alpha = 0.12f),
                        RoundedCornerShape(2.dp),
                    )
            )
        }
    }
}

@Composable
private fun BarRow(label: String, value: Int, max: Int, color: Color) {
    Column(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                label,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f, fill = false),
                maxLines = 1,
            )
            Text("$value", style = MaterialTheme.typography.labelMedium, color = color, fontWeight = FontWeight.Bold)
        }
        Box(
            Modifier
                .fillMaxWidth()
                .height(8.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(4.dp)),
        ) {
            val frac = (value.toFloat() / max).coerceIn(0.02f, 1f)
            Box(
                Modifier
                    .fillMaxWidth(frac)
                    .height(8.dp)
                    .background(color, RoundedCornerShape(4.dp)),
            )
        }
    }
}

@Composable
private fun EmptyHint(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
    )
    Spacer(Modifier.width(0.dp))
}
