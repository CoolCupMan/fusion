package com.fusion.firewall.data

import com.fusion.firewall.data.model.Policy

/** Immutable snapshot of the user's global configuration. */
data class FusionSettings(
    val firewallEnabled: Boolean = false,
    /**
     * Policy applied to apps the user has not confirmed yet. Default ALLOW so
     * enabling Fusion never takes the whole phone offline — only apps you
     * explicitly BLOCK are cut off and monitored.
     */
    val defaultPolicy: Policy = Policy.ALLOW,
    /** When true, brand-new apps raise a personal prompt notification. */
    val promptOnNewApps: Boolean = true,
    /** BinaryCore engine selection. */
    val aiMode: AiMode = AiMode.LOCAL,
    /** Automatically apply BinaryCore recommendations without asking. */
    val aiAutoApply: Boolean = false,
    /** Remote BinaryCore endpoint (used when [aiMode] == REMOTE or HYBRID). */
    val binaryCoreEndpoint: String = "",
    val binaryCoreApiKey: String = "",
    /** Also block traffic for apps that are currently PENDING (default off). */
    val blockPendingByDefault: Boolean = false,
    /** Endpoint for IP intelligence (geo/entity/ASN) enrichment; ipinfo-style JSON. */
    val ipIntelEndpoint: String = "",
    val ipIntelApiKey: String = "",
    /** Allow online lookups for connection intelligence (sends dest IPs to the endpoint). */
    val onlineIntelEnabled: Boolean = false,
    /** Use su for deep, root-level monitoring when the device is already rooted. */
    val rootModeEnabled: Boolean = false,
    /** Realtime monitoring auto-blocks apps whose traffic looks dangerous. */
    val autoBlockDangerous: Boolean = false,
)

enum class AiMode {
    /** On-device heuristic engine, fully offline. */
    LOCAL,

    /** Remote BinaryCore API only. */
    REMOTE,

    /** Local engine first, remote API to enrich/confirm. */
    HYBRID;

    companion object {
        fun fromName(name: String?): AiMode =
            entries.firstOrNull { it.name == name } ?: LOCAL
    }
}
