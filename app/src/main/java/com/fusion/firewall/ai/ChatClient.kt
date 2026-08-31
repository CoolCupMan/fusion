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
        "You are Fusion's built-in assistant, embedded in an Android firewall / DNS " +
            "content-blocker app. Help the user understand network connections, domains, " +
            "trackers, and what apps are doing on their phone, and answer general questions " +
            "clearly and concisely. When given a domain or connection, explain what it is " +
            "likely for and whether it is safe to block."

    suspend fun send(history: List<ChatMessage>, settings: FusionSettings): String =
        withContext(Dispatchers.IO) {
            if (settings.chatApiKey.isBlank()) {
                return@withContext "Set your Claude API key in Settings → AI chat to enable the assistant."
            }
            runCatching { call(history, settings) }.getOrElse { "Error: ${it.message}" }
        }

    private fun call(history: List<ChatMessage>, settings: FusionSettings): String {
        val messages = JSONArray()
        for (m in history.takeLast(20)) {
            messages.put(
                JSONObject()
                    .put("role", if (m.isUser) "user" else "assistant")
                    .put("content", m.text)
            )
        }
        val body = JSONObject()
            .put("model", settings.chatModel.ifBlank { "claude-opus-5" })
            .put("max_tokens", 2048)
            .put("system", SYSTEM_PROMPT)
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
