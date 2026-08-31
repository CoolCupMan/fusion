package com.fusion.firewall.ai

import com.fusion.firewall.data.FusionSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** A single turn in the assistant conversation. */
data class ChatMessage(val role: String, val text: String) {
    val isUser: Boolean get() = role == "user"
}

/**
 * General-purpose AI chat backed by the Claude Messages API. The endpoint, model
 * and API key are user-supplied (Settings) — nothing is hard-coded beyond the
 * public Anthropic endpoint default. Uses raw HTTP (no SDK dependency) with the
 * documented headers: x-api-key + anthropic-version.
 */
object ChatClient {

    private const val SYSTEM_PROMPT =
        "You are Fusion's built-in assistant, embedded INSIDE an Android firewall / DNS " +
            "content-blocker app called Fusion. Answer the user's questions about the app and " +
            "their network directly, by deduction and analysis of the live app state provided " +
            "below — do NOT ask the user to copy-paste anything; you can already see the " +
            "relevant state. Be concise and concrete. When asked how to do something, refer to " +
            "the exact tab/button. When asked about a domain/connection, explain what it is " +
            "likely for and whether blocking it is safe."

    /** Static description of how Fusion works, so the assistant can answer usage questions. */
    private const val APP_GUIDE = """
HOW FUSION WORKS (for answering usage questions):
- It is a non-root, on-device DNS filter (like Pi-hole). It runs a local VPN that intercepts DNS only; blocked domains are sinkholed (NXDOMAIN) instantly, everything else is forwarded, so apps stay online. Apps that use encrypted DNS (DoH/DoT) can bypass filtering.
- Tabs:
  • Dashboard: protection on/off toggle; counters — "Blocked apps", "Pending apps", and "Dropped" (number of DNS lookups blocked while protection is on). A "What does Dropped mean?" help expander explains them.
  • Traffic: live DNS lookups with a BLOCKED/ALLOWED badge and Blocked/Allowed counters. Buttons: "Block all"/"Unblock all" (all currently-visible domains). Per row: Ask AI (local verdict), Ask chat (this assistant), Block/Unblock site (domain), Block/Unblock app. Filters: All/Blocked/Allowed/Malicious/Suspicious.
  • Apps: every internet app with an Allow/Block/Ask selector + data usage; "Block all apps"/"Unblock all".
  • Lists: import block lists from a searchable catalog, a URL, or pasted text; enable/disable lists; whitelist; custom blocked domains; "Filtered connections" (what the lists actually blocked). Supported formats: hosts, AdBlock ||domain^, plain.
  • Threats: dangerous-app analysis (scores apps by their traffic), an "Auto-block dangerous apps" toggle, "Recommended actions", and "Ask AI about blocked apps". Optional root mode for deep monitoring if the device is already rooted.
  • Settings: default policy (Allow/Ask/Block), personal prompts, BinaryCore engine + API, IP-intelligence, root mode, and this AI chat's API key/model.
- Per-app block = sinkhole every DNS lookup from that app. Whitelist always wins over any block list.
"""

    suspend fun send(history: List<ChatMessage>, settings: FusionSettings, appContext: String = ""): String =
        withContext(Dispatchers.IO) {
            if (settings.chatApiKey.isBlank()) {
                return@withContext "Set your Claude API key in Settings → AI chat to enable the assistant."
            }
            runCatching { call(history, settings, appContext) }.getOrElse { "Error: ${it.message}" }
        }

    private fun call(history: List<ChatMessage>, settings: FusionSettings, appContext: String): String {
        val messages = JSONArray()
        for (m in history.takeLast(20)) {
            messages.put(
                JSONObject()
                    .put("role", if (m.isUser) "user" else "assistant")
                    .put("content", m.text)
            )
        }
        val system = buildString {
            append(SYSTEM_PROMPT)
            append("\n").append(APP_GUIDE)
            if (appContext.isNotBlank()) {
                append("\n\nLIVE APP STATE (right now):\n").append(appContext)
            }
        }
        val body = JSONObject()
            .put("model", settings.chatModel.ifBlank { "claude-opus-5" })
            .put("max_tokens", 2048)
            .put("system", system)
            .put("messages", messages)
            .toString()

        val conn = (URL(settings.chatEndpoint.ifBlank { "https://api.anthropic.com/v1/messages" })
            .openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 8000
            readTimeout = 60000
            doOutput = true
            setRequestProperty("content-type", "application/json")
            setRequestProperty("x-api-key", settings.chatApiKey)
            setRequestProperty("anthropic-version", "2023-06-01")
        }
        conn.outputStream.use { it.write(body.toByteArray()) }
        val code = conn.responseCode
        val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        conn.disconnect()
        if (code !in 200..299) return "API error $code: ${shortError(text)}"

        val json = JSONObject(text)
        val content = json.optJSONArray("content") ?: return "(no response)"
        val sb = StringBuilder()
        for (i in 0 until content.length()) {
            val block = content.optJSONObject(i) ?: continue
            if (block.optString("type") == "text") sb.append(block.optString("text"))
        }
        return sb.toString().ifBlank { "(no text in response)" }
    }

    private fun shortError(body: String): String = runCatching {
        JSONObject(body).optJSONObject("error")?.optString("message") ?: body.take(200)
    }.getOrDefault(body.take(200))
}
