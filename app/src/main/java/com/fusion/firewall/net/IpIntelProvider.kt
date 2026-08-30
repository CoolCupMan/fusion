package com.fusion.firewall.net

import com.fusion.firewall.data.FusionSettings
import com.fusion.firewall.data.model.IpIntel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

/**
 * Resolves rich intelligence about the remote end of a connection: reverse DNS,
 * hosting/datacenter classification, and — when the user enables online lookups
 * and configures an endpoint — geolocation, owning entity/vendor, and ASN/route.
 *
 * The online contract is ipinfo-style JSON (documented in the README); the
 * endpoint is user-supplied so no third party is contacted unless the user opts
 * in. Results are cached per IP.
 */
class IpIntelProvider(private val hosts: HostResolver) {

    private val cache = ConcurrentHashMap<String, IpIntel>()
    private val json = Json { ignoreUnknownKeys = true }

    // rDNS/org fragments that identify hosting/cloud/datacenter networks.
    private val hostingVendors = mapOf(
        "amazonaws" to "Amazon AWS", "compute.amazonaws" to "Amazon AWS",
        "googleusercontent" to "Google Cloud", "1e100" to "Google",
        "cloudflare" to "Cloudflare", "azure" to "Microsoft Azure",
        "microsoft" to "Microsoft", "akamai" to "Akamai", "fastly" to "Fastly",
        "digitalocean" to "DigitalOcean", "ovh" to "OVH", "hetzner" to "Hetzner",
        "linode" to "Linode", "oraclecloud" to "Oracle Cloud", "vultr" to "Vultr",
        "facebook" to "Meta/Facebook", "fbcdn" to "Meta/Facebook",
        "gvt1" to "Google", "apple" to "Apple", "icloud" to "Apple iCloud",
    )

    fun cached(ip: String): IpIntel? = cache[ip]

    suspend fun lookup(ip: String, knownHost: String?, settings: FusionSettings): IpIntel =
        withContext(Dispatchers.IO) {
            cache[ip]?.let { return@withContext it }
            val local = localIntel(ip, knownHost)
            val result =
                if (settings.onlineIntelEnabled && settings.ipIntelEndpoint.isNotBlank()) {
                    runCatching { online(ip, settings) ?: local }.getOrElse { local }
                } else local
            cache[ip] = result
            result
        }

    private fun localIntel(ip: String, knownHost: String?): IpIntel {
        val host = knownHost ?: hosts.reverse(ip)
        val vendor = host?.lowercase()?.let { h ->
            hostingVendors.entries.firstOrNull { h.contains(it.key) }?.value
        }
        return IpIntel(
            ip = ip,
            hostname = host,
            org = vendor,
            isHosting = vendor != null,
            source = "local (rDNS)",
            approximate = true,
        )
    }

    private fun online(ip: String, settings: FusionSettings): IpIntel? {
        val base = settings.ipIntelEndpoint.trimEnd('/')
        val urlStr = if (base.contains("{ip}")) base.replace("{ip}", ip) else "$base/$ip"
        val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 4000
            readTimeout = 6000
            setRequestProperty("Accept", "application/json")
            if (settings.ipIntelApiKey.isNotBlank()) {
                setRequestProperty("Authorization", "Bearer ${settings.ipIntelApiKey}")
            }
        }
        val code = conn.responseCode
        if (code !in 200..299) { conn.disconnect(); return null }
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        conn.disconnect()

        val obj = json.parseToJsonElement(text).jsonObject
        fun str(vararg keys: String): String? {
            for (k in keys) obj[k]?.let { return runCatching { it.jsonPrimitive.content }.getOrNull() }
            return null
        }
        val loc = str("loc")
        var lat: Double? = null
        var lon: Double? = null
        if (loc != null && loc.contains(',')) {
            lat = loc.substringBefore(',').trim().toDoubleOrNull()
            lon = loc.substringAfter(',').trim().toDoubleOrNull()
        }
        lat = lat ?: str("latitude", "lat")?.toDoubleOrNull()
        lon = lon ?: str("longitude", "lon", "lng")?.toDoubleOrNull()
        val host = str("hostname") ?: cache[ip]?.hostname ?: hosts.cached(ip)
        val org = str("org", "asn_org", "isp", "company")
        val asn = str("asn", "as")

        return IpIntel(
            ip = ip,
            hostname = host,
            country = str("country", "country_name", "countryCode"),
            region = str("region", "region_name", "state"),
            city = str("city"),
            latitude = lat,
            longitude = lon,
            org = org,
            asn = asn,
            isHosting = str("hosting", "is_hosting")?.equals("true", true) == true ||
                org?.let { o -> hostingVendors.values.any { o.contains(it, true) } } == true,
            abuseContact = str("abuse", "abuse_email"),
            source = "online",
            approximate = true,
        )
    }
}
