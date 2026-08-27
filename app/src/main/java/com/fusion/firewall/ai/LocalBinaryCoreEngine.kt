package com.fusion.firewall.ai

import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.net.HostResolver
import kotlin.math.ln

/**
 * BinaryCore's on-device engine. Fully offline: it scores a connection from
 * signals available on the packet itself plus a bundled reputation set. This is
 * the "local AI feature" that lets Fusion recommend allow/block without any
 * network round-trip or account.
 */
class LocalBinaryCoreEngine(private val hosts: HostResolver) : BinaryCoreEngine {

    override val name: String = "BinaryCore Local"

    // Ports that are unusual for ordinary app traffic and worth flagging.
    private val suspiciousPorts = setOf(23, 25, 445, 1080, 3389, 4444, 5555, 6667, 9001, 31337)
    // Ports considered normal for everyday connectivity.
    private val commonPorts = setOf(53, 80, 123, 443, 853, 993, 995)

    override suspend fun assess(context: ConnectionContext): ThreatAssessment {
        var score = 0
        val reasons = ArrayList<String>()

        val host = context.host
        if (hosts.isKnownTracker(host)) {
            score += 60
            reasons += "known tracker/telemetry endpoint"
        }

        if (context.port in suspiciousPorts) {
            score += 45
            reasons += "unusual port ${context.port}"
        } else if (context.port !in commonPorts && context.port < 1024) {
            score += 15
            reasons += "privileged port ${context.port}"
        }

        // Direct-to-IP with no hostname is a mild signal.
        if (host == null) {
            score += 10
            reasons += "no DNS name (raw IP)"
        } else {
            val entropy = domainEntropy(host)
            if (entropy > 3.6 && host.length > 18) {
                score += 25
                reasons += "high-entropy domain (possible DGA)"
            }
        }

        // Cleartext HTTP for a non-system app leaks data.
        if (context.port == 80 && !context.isSystemApp) {
            score += 10
            reasons += "cleartext HTTP"
        }

        val verdict = when {
            score >= 70 -> Verdict.MALICIOUS
            score >= 40 -> Verdict.SUSPICIOUS
            score >= 15 -> Verdict.UNKNOWN
            else -> Verdict.SAFE
        }
        val recommended = when (verdict) {
            Verdict.MALICIOUS -> Policy.BLOCK
            Verdict.SUSPICIOUS -> Policy.BLOCK
            Verdict.SAFE -> Policy.ALLOW
            Verdict.UNKNOWN -> Policy.PENDING
        }
        val confidence = (score.coerceIn(0, 100)) / 100f

        return ThreatAssessment(
            verdict = verdict,
            confidence = if (verdict == Verdict.SAFE) 0.6f else confidence,
            reason = if (reasons.isEmpty()) "No risk signals detected" else reasons.joinToString(", "),
            recommendedPolicy = recommended,
            source = name,
        )
    }

    /** Shannon entropy over the registrable label, used as a DGA heuristic. */
    private fun domainEntropy(host: String): Double {
        val label = host.substringBefore('.').ifEmpty { host }
        if (label.isEmpty()) return 0.0
        val freq = label.groupingBy { it }.eachCount()
        val len = label.length.toDouble()
        return freq.values.sumOf { c ->
            val p = c / len
            -p * ln(p) / ln(2.0)
        }
    }
}
