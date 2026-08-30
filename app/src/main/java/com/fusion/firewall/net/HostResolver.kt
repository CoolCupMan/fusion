package com.fusion.firewall.net

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Best-effort IP -> hostname resolution plus a small on-device reputation list.
 * DNS query names parsed from the packet stream are fed back in via [remember]
 * so the UI can label a flow the moment it appears, without a blocking lookup.
 */
class HostResolver {

    private val ipToHost = ConcurrentHashMap<String, String>()

    /** Known tracker / advertising / telemetry / malware domain fragments (offline block list). */
    private val trackerFragments = listOf(
        // Ad networks & exchanges
        "doubleclick", "googlesyndication", "googleadservices", "adservice",
        "adsystem", "admob", "adcolony", "applovin", "vungle", "inmobi",
        "mopub", "pubmatic", "rubiconproject", "openx", "adnxs", "adsrvr",
        "smaato", "mgid", "revcontent", "propellerads", "popads", "adform",
        "criteo", "taboola", "outbrain", "moatads", "smartadserver", "teads",
        // Analytics & telemetry
        "google-analytics", "googletagmanager", "app-measurement", "firebase",
        "crashlytics", "amplitude", "mixpanel", "segment.io", "branch.io",
        "adjust.com", "appsflyer", "flurry", "chartboost", "kochava", "singular",
        "scorecardresearch", "quantserve", "comscore", "newrelic", "datadog",
        "bugsnag", "sentry.io", "instabug", "umeng", "onesignal", "leanplum",
        "clevertap", "braze", "airship", "swrve", "localytics", "heapanalytics",
        "fullstory", "hotjar", "mouseflow", "clarity.ms", "yandex", "appcenter.ms",
        // Social trackers / CDNs used for tracking
        "facebook.com/tr", "graph.facebook", "connect.facebook", "fbcdn",
        "ads.tiktok", "analytics.tiktok", "business-api.tiktok", "mail.ru",
        "vk.com", "hotwords", "sharethis", "addthis",
        // Vendor telemetry
        "metric.gstatic", "gvt2.com", "settings.crashlytics", "in.appcenter",
        "self.events.data.microsoft", "vortex.data.microsoft", "watson.telemetry",
        // Malware / C2 / suspicious hosting patterns (heuristic fragments)
        "malware", "phishing", "botnet", "c2server", "cobaltstrike",
        "duckdns.org", "no-ip.org", "ngrok.io", "serveo.net",
    )

    fun remember(ip: String, host: String) {
        if (host.isNotBlank()) ipToHost[ip] = host
    }

    fun cached(ip: String): String? = ipToHost[ip]

    /** Blocking reverse lookup — call off the packet thread only. */
    fun reverse(ip: String): String? {
        cached(ip)?.let { return it }
        return runCatching {
            val host = InetAddress.getByName(ip).canonicalHostName
            if (host != ip) {
                ipToHost[ip] = host
                host
            } else null
        }.getOrNull()
    }

    fun isKnownTracker(host: String?): Boolean {
        val h = host?.lowercase() ?: return false
        return trackerFragments.any { h.contains(it) }
    }
}
