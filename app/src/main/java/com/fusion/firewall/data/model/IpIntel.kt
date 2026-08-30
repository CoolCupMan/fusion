package com.fusion.firewall.data.model

/**
 * Everything Fusion can learn about the remote end of a connection. Geolocation
 * from an IP is APPROXIMATE (city-level at best) — it is the location of the
 * server/route, never a person's GPS position. Entity/vendor data comes from
 * the network registry (RIR/WHOIS) via the configured intelligence endpoint.
 */
data class IpIntel(
    val ip: String,
    val hostname: String? = null,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    /** Owning organization / ISP / vendor (the "entity"). */
    val org: String? = null,
    /** Autonomous System number + name (the network route owner). */
    val asn: String? = null,
    /** True when the address belongs to a hosting/cloud/datacenter provider. */
    val isHosting: Boolean = false,
    val abuseContact: String? = null,
    val source: String = "local",
    val approximate: Boolean = true,
) {
    val hasLocation: Boolean get() = latitude != null && longitude != null

    fun locationLine(): String? {
        val parts = listOfNotNull(city, region, country).filter { it.isNotBlank() }
        return if (parts.isEmpty()) null else parts.joinToString(", ")
    }

    fun coordsLine(): String? =
        if (hasLocation) "%.4f, %.4f".format(latitude, longitude) else null
}
