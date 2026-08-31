package com.fusion.firewall.ai

import com.fusion.firewall.data.ChatProvider
import com.fusion.firewall.data.FusionSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

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
            if (settings.activeChatKey.isBlank()) {
                return@withContext "Set your ${settings.chatProvider.label} API key in Settings → AI chat to enable the assistant."
            }
            val system = buildSystem(appContext)
            runCatching {
                when (settings.chatProvider) {
                    ChatProvider.ANTHROPIC -> callAnthropic(history, settings, system)
                    ChatProvider.OPENAI -> callOpenAI(history, settings, system)
                    ChatProvider.GOOGLE -> callGoogle(history, settings, system)
                }
            }.getOrElse { "Error: ${it.message}" }
        }

    private fun buildSystem(appContext: String): String = buildString {
        append(SYSTEM_PROMPT)
        append("\n").append(APP_GUIDE)
        if (appContext.isNotBlank()) append("\n\nLIVE APP STATE (right now):\n").append(appContext)
    }

    private fun recent(history: List<ChatMessage>) = history.takeLast(20)

    // --- Anthropic (Claude) --------------------------------------------------
    private fun callAnthropic(history: List<ChatMessage>, settings: FusionSettings, system: String): String {
        val messages = JSONArray()
        for (m in recent(history)) {
            messages.put(JSONObject().put("role", if (m.isUser) "user" else "assistant").put("content", m.text))
        }
        val body = JSONObject()
            .put("model", settings.chatModel.ifBlank { "claude-opus-5" })
            .put("max_tokens", 2048)
            .put("system", system)
            .put("messages", messages)
            .toString()
        val (code, text) = post(
            settings.chatEndpoint.ifBlank { "https://api.anthropic.com/v1/messages" },
            body,
            mapOf(
                "content-type" to "application/json",
                "x-api-key" to settings.chatApiKey,
                "anthropic-version" to "2023-06-01",
            ),
        )
        if (code !in 200..299) return "API error $code: ${shortError(text)}"
        val content = JSONObject(text).optJSONArray("content") ?: return "(no response)"
        val sb = StringBuilder()
        for (i in 0 until content.length()) {
            val block = content.optJSONObject(i) ?: continue
            if (block.optString("type") == "text") sb.append(block.optString("text"))
        }
        return sb.toString().ifBlank { "(no text in response)" }
    }

    // --- OpenAI --------------------------------------------------------------
    private fun callOpenAI(history: List<ChatMessage>, settings: FusionSettings, system: String): String {
        val messages = JSONArray()
        messages.put(JSONObject().put("role", "system").put("content", system))
        for (m in recent(history)) {
            messages.put(JSONObject().put("role", if (m.isUser) "user" else "assistant").put("content", m.text))
        }
        val body = JSONObject()
            .put("model", settings.openaiModel.ifBlank { "gpt-4o-mini" })
            .put("max_tokens", 2048)
            .put("messages", messages)
            .toString()
        val (code, text) = post(
            "https://api.openai.com/v1/chat/completions",
            body,
            mapOf(
                "content-type" to "application/json",
                "Authorization" to "Bearer ${settings.openaiApiKey}",
            ),
        )
        if (code !in 200..299) return "API error $code: ${shortError(text)}"
        val choice = JSONObject(text).optJSONArray("choices")?.optJSONObject(0)
        return choice?.optJSONObject("message")?.optString("content")?.ifBlank { "(no text)" }
            ?: "(no response)"
    }

    // --- Google Gemini -------------------------------------------------------
    private fun callGoogle(history: List<ChatMessage>, settings: FusionSettings, system: String): String {
        val model = settings.googleModel.ifBlank { "gemini-1.5-flash" }
        val contents = JSONArray()
        for (m in recent(history)) {
            contents.put(
                JSONObject()
                    .put("role", if (m.isUser) "user" else "model")
                    .put("parts", JSONArray().put(JSONObject().put("text", m.text)))
            )
        }
        val body = JSONObject()
            .put("system_instruction", JSONObject().put("parts", JSONArray().put(JSONObject().put("text", system))))
            .put("contents", contents)
            .put("generationConfig", JSONObject().put("maxOutputTokens", 2048))
            .toString()
        val key = URLEncoder.encode(settings.googleApiKey, "UTF-8")
        val (code, text) = post(
            "https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent?key=$key",
            body,
            mapOf("content-type" to "application/json"),
        )
        if (code !in 200..299) return "API error $code: ${shortError(text)}"
        val parts = JSONObject(text).optJSONArray("candidates")?.optJSONObject(0)
            ?.optJSONObject("content")?.optJSONArray("parts") ?: return "(no response)"
        val sb = StringBuilder()
        for (i in 0 until parts.length()) sb.append(parts.optJSONObject(i)?.optString("text").orEmpty())
        return sb.toString().ifBlank { "(no text in response)" }
    }

    /** POST JSON, return (status, bodyText). */
    private fun post(url: String, body: String, headers: Map<String, String>): Pair<Int, String> {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 8000
            readTimeout = 60000
            doOutput = true
            headers.forEach { (k, v) -> setRequestProperty(k, v) }
        }
        conn.outputStream.use { it.write(body.toByteArray()) }
        val code = conn.responseCode
        val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        conn.disconnect()
        return code to text
    }

    private fun shortError(body: String): String = runCatching {
        JSONObject(body).optJSONObject("error")?.optString("message") ?: body.take(200)
    }.getOrDefault(body.take(200))
}
