package com.fusion.firewall.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Downloads and parses block lists. Understands both hosts-file format
 * (`0.0.0.0 ads.example.com`) and plain one-domain-per-line lists.
 */
object BlockListImporter {

    suspend fun fromUrl(url: String): Set<String> = withContext(Dispatchers.IO) {
        val conn = (URL(url.trim()).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 8000
            readTimeout = 20000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "Fusion/1.0")
        }
        val code = conn.responseCode
        if (code !in 200..299) {
            conn.disconnect()
            throw IllegalStateException("HTTP $code")
        }
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        conn.disconnect()
        parse(text)
    }

    fun parse(text: String): Set<String> {
        val out = HashSet<String>()
        for (rawLine in text.lineSequence()) {
            var line = rawLine.trim()
            if (line.isEmpty()) continue
            val hash = line.indexOf('#')
            if (hash >= 0) line = line.substring(0, hash).trim()
            if (line.isEmpty()) continue

            val tokens = line.split(Regex("\\s+"))
            val candidate = when {
                tokens.size >= 2 && looksLikeIp(tokens[0]) -> tokens[1]
                tokens.size == 1 -> tokens[0]
                else -> continue
            }
            val domain = candidate.lowercase().removePrefix("*.").trimEnd('.')
            if (isValidDomain(domain)) out += domain
        }
        return out
    }

    private fun looksLikeIp(s: String): Boolean =
        s == "0.0.0.0" || s == "127.0.0.1" || s == "::1" || s == "::" ||
            s.count { it == '.' } == 3 && s.all { it.isDigit() || it == '.' }

    private fun isValidDomain(d: String): Boolean {
        if (d.length < 3 || d.length > 253) return false
        if (!d.contains('.')) return false
        if (d == "localhost" || d.endsWith(".localhost")) return false
        return d.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }
    }
}
