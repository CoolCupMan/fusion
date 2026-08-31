package com.fusion.firewall.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import com.fusion.firewall.ai.ChatMessage
import com.fusion.firewall.ui.FusionViewModel

@Composable
fun ChatScreen(viewModel: FusionViewModel, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val messages by viewModel.chatMessages.collectAsState()
    val busy by viewModel.chatBusy.collectAsState()
    val settings by viewModel.settings.collectAsState()
    var input by remember { mutableStateOf("") }

    Column(modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Fusion Assistant", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Row {
                TextButton(onClick = { viewModel.clearChat() }) { Text("Clear") }
                TextButton(onClick = onClose) { Text("Close") }
            }
        }
        if (settings.activeChatKey.isBlank()) {
            Text(
                "Add your ${settings.chatProvider.label} API key in Settings → AI chat to ask " +
                    "anything about your connections and apps.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        } else if (messages.isEmpty()) {
            Text(
                "Ask me anything about Fusion — I can see your current protection state, live " +
                    "traffic, blocked apps, block lists and flagged apps, and I can act for you. " +
                    "Try: \"why is X blocked?\", \"which apps look dangerous?\", \"block all " +
                    "social media\", \"block facebook\", or \"block ads.example.com\".",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        LazyColumn(
            Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(messages) { m -> Bubble(m) }
            if (busy) {
                item {
                    Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.padding(end = 8.dp))
                        Text("Thinking…", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                placeholder = { Text("Ask anything…") },
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = { viewModel.sendChat(input); input = "" },
                enabled = input.isNotBlank() && !busy,
            ) { Text("Send") }
        }
    }
}

@Composable
private fun Bubble(m: ChatMessage) {
    val color = if (m.isUser) MaterialTheme.colorScheme.primary.copy(alpha = 0.16f)
    else MaterialTheme.colorScheme.surfaceVariant
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (m.isUser) Arrangement.End else Arrangement.Start,
    ) {
        Surface(color = color, shape = RoundedCornerShape(12.dp), modifier = Modifier.widthIn(max = 320.dp)) {
            Text(
                m.text,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
        }
    }
}
