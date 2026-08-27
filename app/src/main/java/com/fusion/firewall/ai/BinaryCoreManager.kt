package com.fusion.firewall.ai

import com.fusion.firewall.data.AiMode
import com.fusion.firewall.data.FusionSettings
import com.fusion.firewall.net.HostResolver

/**
 * Routes an assessment to the engine chosen in Settings. In HYBRID mode the
 * local engine runs first (instant, offline) and the remote BinaryCore API is
 * consulted to enrich or override low-confidence local verdicts.
 */
class BinaryCoreManager(hosts: HostResolver) {

    private val local = LocalBinaryCoreEngine(hosts)

    suspend fun assess(context: ConnectionContext, settings: FusionSettings): ThreatAssessment {
        return when (settings.aiMode) {
            AiMode.LOCAL -> local.assess(context)
            AiMode.REMOTE -> remote(settings)?.assess(context) ?: local.assess(context)
            AiMode.HYBRID -> {
                val localResult = local.assess(context)
                val remote = remote(settings) ?: return localResult
                if (localResult.confidence >= 0.7f) return localResult
                val remoteResult = remote.assess(context)
                if (remoteResult.verdict == Verdict.UNKNOWN) localResult else remoteResult
            }
        }
    }

    private fun remote(settings: FusionSettings): BinaryCoreEngine? =
        if (settings.binaryCoreEndpoint.isBlank()) null
        else RemoteBinaryCoreClient(settings.binaryCoreEndpoint, settings.binaryCoreApiKey)
}
