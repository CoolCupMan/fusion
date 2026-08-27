package com.fusion.firewall.data.model

/** Transport protocol of an observed packet. */
enum class Transport { TCP, UDP, ICMP, OTHER }

/** Direction relative to the device. */
enum class Direction { OUTBOUND, INBOUND }

/**
 * A single realtime connection attempt observed on the tunnel. These are the
 * "not confirmed / personally prompted" flows the dashboard visualizes: an app
 * trying to reach the network before (or after) the user has decided on it.
 */
data class ConnectionEvent(
    val timestamp: Long,
    val uid: Int,
    val packageName: String?,
    val appLabel: String?,
    val transport: Transport,
    val direction: Direction,
    val remoteIp: String,
    val remotePort: Int,
    val localPort: Int,
    val hostname: String?,
    val bytes: Int,
    val allowed: Boolean,
    val flagged: Boolean = false,
    val flagReason: String? = null,
) {
    val id: String get() = "$uid|$remoteIp|$remotePort|$transport"
}
