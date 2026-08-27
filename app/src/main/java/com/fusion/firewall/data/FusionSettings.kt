package com.fusion.firewall.data

import com.fusion.firewall.data.model.Policy

/** Immutable snapshot of the user's global configuration. */
data class FusionSettings(
    val firewallEnabled: Boolean = false,
    /** Policy applied to apps the user has not confirmed yet. */
    val defaultPolicy: Policy = Policy.PENDING,
    /** When true, brand-new apps raise a personal prompt notification. */
    val promptOnNewApps: Boolean = true,
    /** BinaryCore engine selection. */
    val aiMode: AiMode = AiMode.LOCAL,
    /** Automatically apply BinaryCore recommendations without asking. */
    val aiAutoApply: Boolean = false,
    /** Remote BinaryCore endpoint (used when [aiMode] == REMOTE or HYBRID). */
    val binaryCoreEndpoint: String = "",
    val binaryCoreApiKey: String = "",
    /** Also block traffic for apps that are currently PENDING. */
    val blockPendingByDefault: Boolean = true,
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
