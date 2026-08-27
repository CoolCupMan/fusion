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

    /** Known tracker / advertising / telemetry domain fragments (offline set). */
    private val trackerFragments = listOf(
        "doubleclick", "googlesyndication", "google-analytics", "googleadservices",
        "adservice", "adsystem", "admob", "app-measurement", "crashlytics",
        "facebook.com/tr", "graph.facebook", "connect.facebook", "fbcdn",
        "amplitude", "mixpanel", "segment.io", "branch.io", "adjust.com",
        "appsflyer", "flurry", "chartboost", "unity3d.com", "unityads",
        "scorecardresearch", "criteo", "taboola", "outbrain", "moatads",
        "bugsnag", "sentry.io", "yandex", "mail.ru", "onesignal", "kochava",
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
