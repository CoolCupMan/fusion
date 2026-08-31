package com.fusion.firewall.net

/**
 * Traffic-type rubrics for a DNS content-blocker. Because Fusion sees traffic at
 * the DNS layer (domain names + owning app), a "traffic type" is inferred from
 * the domain, not from the wire protocol. These families collapse the long list
 * of possible network/app traffic categories into the ones a DNS filter can
 * actually recognize and block in bulk.
 */
enum class TrafficCategory(val label: String) {
    ADS("Advertising"),
    ANALYTICS("Analytics & tracking"),
    TELEMETRY("Telemetry & diagnostics"),
    CRASH("Crash reporting"),
    PUSH("Push notifications"),
    ATTRIBUTION("Install attribution"),
    CDN("CDN & content delivery"),
    CLOUD_API("Cloud & API"),
    SOCIAL("Social media"),
    STREAMING("Video & audio streaming"),
    MESSAGING("Messaging & chat"),
    VOIP("Calls & WebRTC"),
    EMAIL("Email"),
    MAPS("Maps & location"),
    WEATHER("Weather"),
    GAMING("Gaming services"),
    ECOMMERCE("Shopping & e-commerce"),
    FINANCE("Finance & banking"),
    SEARCH("Search"),
    UPDATES("Software & OS updates"),
    IOT("Smart home & IoT"),
    SECURITY("Security & auth"),
    AI("AI assistants"),
    DNS("Encrypted DNS (DoH/DoT)"),
    ADULT("Adult"),
    OTHER("Other / uncategorized"),
}

/**
 * Classifies a domain into a [TrafficCategory] by matching known fragments.
 * Ordered most-specific first (ads/analytics/telemetry before the broad service
 * families), so a tracking host on a CDN is still counted as tracking. Best
 * effort — unmatched domains fall through to [TrafficCategory.OTHER].
 */
object TrafficCategorizer {

    private val rules: List<Pair<TrafficCategory, List<String>>> = listOf(
        TrafficCategory.ADS to listOf(
            "doubleclick", "googlesyndication", "googleadservices", "adservice", "adsystem",
            "admob", "adcolony", "applovin", "vungle", "inmobi", "mopub", "pubmatic",
            "rubiconproject", "openx", "adnxs", "adsrvr", "smaato", "mgid", "revcontent",
            "propellerads", "popads", "adform", "criteo", "taboola", "outbrain", "moatads",
            "smartadserver", "teads", "/ads", "ads.", ".ads", "adserver", "banner",
        ),
        TrafficCategory.ANALYTICS to listOf(
            "google-analytics", "googletagmanager", "app-measurement", "amplitude", "mixpanel",
            "segment.io", "scorecardresearch", "quantserve", "comscore", "heapanalytics",
            "fullstory", "hotjar", "mouseflow", "clarity.ms", "umeng", "leanplum", "clevertap",
            "braze", "localytics", "analytics.", "metrics.", "telemetry.stats", "stats.",
        ),
        TrafficCategory.TELEMETRY to listOf(
            "telemetry", "vortex.data.microsoft", "self.events.data.microsoft", "watson.telemetry",
            "metric.gstatic", "gvt2.com", "diagnostic", "insights.", "logging.", "log-ingest",
        ),
        TrafficCategory.CRASH to listOf(
            "crashlytics", "sentry.io", "bugsnag", "instabug", "appcenter.ms", "crashreport",
            "newrelic", "datadog", "raygun", "rollbar",
        ),
        TrafficCategory.ATTRIBUTION to listOf(
            "adjust.com", "appsflyer", "branch.io", "kochava", "singular.net", "tenjin",
            "attribution", "tune.com",
        ),
        TrafficCategory.PUSH to listOf(
            "fcm.googleapis", "mtalk.google", "android.googleapis.com/gcm", "onesignal",
            "airship", "urbanairship", "pushwoosh", "pusher.com", "notify.", "push.",
        ),
        TrafficCategory.AI to listOf(
            "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.google",
            "generativelanguage.googleapis", "perplexity.ai", "x.ai", "copilot.microsoft",
            "huggingface", "bard.google",
        ),
        TrafficCategory.SOCIAL to listOf(
            "facebook", "fbcdn", "instagram", "cdninstagram", "tiktok", "tiktokcdn", "snapchat",
            "twitter", "twimg", "x.com", "reddit", "redd.it", "pinterest", "pinimg", "linkedin",
            "licdn", "threads.net", "bsky", "mastodon", "tumblr", "vk.com", "weibo",
        ),
        TrafficCategory.STREAMING to listOf(
            "youtube", "ytimg", "googlevideo", "netflix", "nflxvideo", "nflximg", "spotify",
            "scdn.co", "primevideo", "aiv-cdn", "disney", "dssott", "hulu", "twitch", "ttvnw",
            "soundcloud", "deezer", "tidal", "pandora", "hbomax", "max.com", "paramount",
            "vimeo", "dailymotion", "video", "stream",
        ),
        TrafficCategory.MESSAGING to listOf(
            "whatsapp", "telegram", "t.me", "signal.org", "discord", "discordapp", "messenger",
            "viber", "line.me", "kakao", "wechat", "weixin", "slack", "matrix.org",
        ),
        TrafficCategory.VOIP to listOf(
            "zoom.us", "zoomgov", "webex", "teams.microsoft", "skype", "stun.", "turn.",
            "voip", "sip.", "twilio", "agora.io", "sinch", "webrtc",
        ),
        TrafficCategory.EMAIL to listOf(
            "mail.google", "gmail", "imap", "smtp", "outlook", "office365", "hotmail",
            "protonmail", "proton.me", "yahoo.mail", "mail.", "zoho.mail", "fastmail",
        ),
        TrafficCategory.MAPS to listOf(
            "maps.google", "maps.gstatic", "mapbox", "openstreetmap", "here.com", "tomtom",
            "waze", "geocode", "location", "geo.", "ipgeolocation", "tile.",
        ),
        TrafficCategory.WEATHER to listOf(
            "weather", "accuweather", "openweathermap", "wunderground", "met.no", "meteo",
            "windy.com", "forecast",
        ),
        TrafficCategory.GAMING to listOf(
            "unity3d", "unityads", "supercell", "king.com", "miniclip", "roblox", "minecraft",
            "epicgames", "steampowered", "playfab", "gameanalytics", "nianticlabs", "gameloft",
        ),
        TrafficCategory.FINANCE to listOf(
            "paypal", "stripe.com", "revolut", "n26", "wise.com", "coinbase", "binance",
            "klarna", "venmo", "cash.app", "plaid.com", "bank", "visa.com", "mastercard",
        ),
        TrafficCategory.ECOMMERCE to listOf(
            "amazon", "ssl-images-amazon", "ebay", "ebaystatic", "aliexpress", "alicdn",
            "etsy", "shein", "temu", "zalando", "shopify", "mercado", "checkout",
        ),
        TrafficCategory.SEARCH to listOf(
            "google.com/search", "bing.com", "duckduckgo", "search.", "yandex.com/search",
            "baidu", "ecosia", "qwant",
        ),
        TrafficCategory.UPDATES to listOf(
            "update", "dl.google", "play.googleapis", "android.clients.google", "gvt1.com",
            "swcdn.apple", "mesu.apple", "download.windowsupdate", "packages.", "repo.",
            "ota.", "fdroid",
        ),
        TrafficCategory.IOT to listOf(
            "tuya", "smartthings", "philips-hue", "meethue", "mihome", "xiaomi.iot", "ring.com",
            "wyze", "nest.com", "iot.", "smartlife", "tplinkcloud",
        ),
        TrafficCategory.SECURITY to listOf(
            "oauth", "accounts.google", "login.", "auth.", "okta", "onelogin", "cloudflareaccess",
            "digicert", "letsencrypt", "ocsp", "pki.", "crl.", "verisign", "certificate",
        ),
        TrafficCategory.DNS to listOf(
            "dns.google", "cloudflare-dns", "one.one.one.one", "dns.quad9", "doh.", "dot.",
            "dns.adguard", "dns.nextdns", "mozilla.cloudflare-dns",
        ),
        TrafficCategory.ADULT to listOf(
            "porn", "xvideos", "xnxx", "pornhub", "xhamster", "redtube", "onlyfans", "adult",
        ),
        TrafficCategory.PUSH to listOf("firebaseinstallations", "firebaseremoteconfig"),
        // Broad content delivery + cloud/API fall near the end so specific
        // services above win first.
        TrafficCategory.CDN to listOf(
            "cloudfront", "akamai", "akamaized", "fastly", "cdn.", "cdn77", "stackpathcdn",
            "edgekey", "edgesuite", "llnwd", "cachefly", "jsdelivr", "cdnjs", "unpkg", "gstatic",
        ),
        TrafficCategory.CLOUD_API to listOf(
            "amazonaws", "azurewebsites", "azure.com", "googleapis", "appspot", "herokuapp",
            "firebaseio", "firestore", "api.", "graphql", "grpc", "backend.", "cloudfunctions",
            "digitaloceanspaces", "cloudflarestorage",
        ),
    )

    fun classify(domain: String?): TrafficCategory {
        val h = domain?.lowercase()?.trim() ?: return TrafficCategory.OTHER
        if (h.isEmpty()) return TrafficCategory.OTHER
        for ((cat, keys) in rules) {
            if (keys.any { h.contains(it) }) return cat
        }
        return TrafficCategory.OTHER
    }
}
