package com.fusion.firewall.ai

import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.data.model.Transport

/** The verdict BinaryCore returns for a connection. */
enum class Verdict { SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN }

/** Everything BinaryCore needs to reason about a single flow. */
data class ConnectionContext(
    val appLabel: String,
    val packageName: String,
    val isSystemApp: Boolean,
    val host: String?,
    val ip: String,
    val port: Int,
    val transport: Transport,
)

/**
 * A BinaryCore assessment: what the flow is, how sure we are, and the firewall
 * decision it recommends. [source] names which engine produced it.
 */
data class ThreatAssessment(
    val verdict: Verdict,
    val confidence: Float,
    val reason: String,
    val recommendedPolicy: Policy,
    val source: String,
) {
    companion object {
        fun unknown(source: String) = ThreatAssessment(
            verdict = Verdict.UNKNOWN,
            confidence = 0f,
            reason = "No signal",
            recommendedPolicy = Policy.PENDING,
            source = source,
        )
    }
}

/**
 * BinaryCore engine contract. Implementations may run fully on-device
 * ([LocalBinaryCoreEngine]) or call the BinaryCore API ([RemoteBinaryCoreClient]).
 */
interface BinaryCoreEngine {
    val name: String
    suspend fun assess(context: ConnectionContext): ThreatAssessment
}
