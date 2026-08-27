package com.fusion.firewall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.ai.Verdict
import com.fusion.firewall.data.model.Policy
import java.util.Locale

@Composable
fun StatCard(title: String, value: String, accent: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(value, style = MaterialTheme.typography.headlineMedium, color = accent, fontWeight = FontWeight.Bold)
            Text(title, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        }
    }
}

@Composable
fun PolicySelector(current: Policy, onSelect: (Policy) -> Unit, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        PolicyChip("Allow", current == Policy.ALLOW, MaterialTheme.colorScheme.primary) { onSelect(Policy.ALLOW) }
        PolicyChip("Block", current == Policy.BLOCK, MaterialTheme.colorScheme.error) { onSelect(Policy.BLOCK) }
        PolicyChip("Ask", current == Policy.PENDING, MaterialTheme.colorScheme.secondary) { onSelect(Policy.PENDING) }
    }
}

@Composable
private fun PolicyChip(label: String, selected: Boolean, accent: Color, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = accent.copy(alpha = 0.22f),
            selectedLabelColor = accent,
        ),
    )
}

@Composable
fun VerdictBadge(verdict: Verdict, confidence: Float) {
    val (color, text) = when (verdict) {
        Verdict.SAFE -> MaterialTheme.colorScheme.primary to "Safe"
        Verdict.SUSPICIOUS -> Color(0xFFFFB020) to "Suspicious"
        Verdict.MALICIOUS -> MaterialTheme.colorScheme.error to "Malicious"
        Verdict.UNKNOWN -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f) to "Unknown"
    }
    Surface(color = color.copy(alpha = 0.18f), shape = RoundedCornerShape(8.dp)) {
        Text(
            "$text · ${(confidence * 100).toInt()}%",
            color = color,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}

@Composable
fun SectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        modifier = modifier.fillMaxWidth().padding(vertical = 4.dp),
    )
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = bytes / 1024.0
    var i = 0
    while (value >= 1024 && i < units.size - 1) {
        value /= 1024.0
        i++
    }
    return String.format(Locale.US, "%.1f %s", value, units[i])
}
