package com.fusion.firewall.data.model

/**
 * Per-app firewall decision.
 *
 *  - [ALLOW]   Traffic is permanently permitted. The app bypasses the Fusion
 *              tunnel entirely and reaches the network normally.
 *  - [BLOCK]   Traffic is permanently denied. The app is routed into the tunnel
 *              and its packets are dropped, so it has no connectivity.
 *  - [PENDING] The app has not been confirmed by the user yet. It is handled by
 *              the global default policy and surfaced for a personal prompt.
 */
enum class Policy {
    ALLOW,
    BLOCK,
    PENDING;

    companion object {
        fun fromName(name: String?): Policy =
            entries.firstOrNull { it.name == name } ?: PENDING
    }
}
