package com.fusion.firewall.data.model

/** A firewall rule bound to a single installed application. */
data class AppRule(
    val packageName: String,
    val uid: Int,
    val label: String,
    val policy: Policy,
    val system: Boolean = false,
    val updatedAt: Long = System.currentTimeMillis(),
) {
    val isConfirmed: Boolean get() = policy != Policy.PENDING
}
