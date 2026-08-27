package com.fusion.firewall.ai

import com.fusion.firewall.data.model.Policy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection
import java.net.URL

/**
 * Talks to the BinaryCore API. The endpoint and API key are supplied by the user
 * in Settings; nothing is hard-coded, so this integrates with whichever
 * BinaryCore deployment the user points it at. The request/response schema is a
 * simple, documented JSON contract (see README).
 */
class RemoteBinaryCoreClient(
    private val endpoint: String,
    private val apiKey: String,
) : BinaryCoreEngine {

    override val name: String = "BinaryCore API"

    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private data class Request(
        val app: String,
        @SerialName("package") val pkg: String,
        val system: Boolean,
        val host: String?,
        val ip: String,
        val port: Int,
        val transport: String,
    )

    @Serializable
    private data class Response(
        val verdict: String? = null,
        val confidence: Float = 0f,
        val reason: String? = null,
        @SerialName("recommended_policy") val recommendedPolicy: String? = null,
    )

    override suspend fun assess(context: ConnectionContext): ThreatAssessment =
        withContext(Dispatchers.IO) {
            if (endpoint.isBlank()) return@withContext ThreatAssessment.unknown(name)
            runCatching { call(context) }.getOrElse {
                ThreatAssessment(
                    verdict = Verdict.UNKNOWN,
                    confidence = 0f,
                    reason = "BinaryCore API unreachable: ${it.message}",
                    recommendedPolicy = Policy.PENDING,
                    source = name,
                )
            }
        }

    private fun call(context: ConnectionContext): ThreatAssessment {
        val body = json.encodeToString(
            Request(
                app = context.appLabel,
                pkg = context.packageName,
                system = context.isSystemApp,
                host = context.host,
                ip = context.ip,
                port = context.port,
                transport = context.transport.name,
            )
        )
        val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 4000
            readTimeout = 6000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            if (apiKey.isNotBlank()) setRequestProperty("Authorization", "Bearer $apiKey")
        }
        conn.outputStream.use { it.write(body.toByteArray()) }
        val code = conn.responseCode
        if (code !in 200..299) {
            conn.disconnect()
            return ThreatAssessment(
                Verdict.UNKNOWN, 0f, "BinaryCore API HTTP $code", Policy.PENDING, name
            )
        }
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        conn.disconnect()
        val parsed = json.decodeFromString<Response>(text)
        val verdict = runCatching { Verdict.valueOf(parsed.verdict?.uppercase() ?: "UNKNOWN") }
            .getOrDefault(Verdict.UNKNOWN)
        return ThreatAssessment(
            verdict = verdict,
            confidence = parsed.confidence,
            reason = parsed.reason ?: "BinaryCore API assessment",
            recommendedPolicy = Policy.fromName(parsed.recommendedPolicy?.uppercase()),
            source = name,
        )
    }
}
