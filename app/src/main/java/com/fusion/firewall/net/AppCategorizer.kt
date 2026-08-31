package com.fusion.firewall.net

/** Fusion's app rubrics for bulk block/unblock. */
enum class AppCategory(val label: String) {
    SOCIAL("Social media"),
    COMMUNICATION("Messaging & calls"),
    FINANCE("Finance & banking"),
    SHOPPING("Shopping"),
    MEDIA("Media & streaming"),
    GAMES("Games"),
    MAPS("Maps & navigation"),
    WEATHER("Weather"),
    HEALTH("Health & fitness"),
    FOOD("Food & delivery"),
    TRAVEL("Travel & transport"),
    DATING("Dating"),
    PHOTO("Photo & camera"),
    CLOUD("Cloud & storage"),
    IOT("Smart home & IoT"),
    SECURITY("Security & privacy"),
    BROWSERS("Browsers & network"),
    PRODUCTIVITY("Productivity"),
    EDUCATION("Science & learning"),
    NEWS("News & knowledge"),
    TOOLS("Tools & utilities"),
    SYSTEM("System, services & daemons"),
    OTHER("Other apps"),
}

/**
 * Heuristic app categorizer: assigns each app to a rubric from its package name
 * and label (plus the system flag), and derives a vendor from the package. Used
 * for "block/unblock a whole category / vendor" in the Apps tab. Heuristics are
 * best-effort — the user can always fine-tune individual apps.
 */
object AppCategorizer {

    // Ordered most-specific first; the first matching rubric wins.
    private val rules: List<Pair<AppCategory, List<String>>> = listOf(
        AppCategory.FINANCE to listOf(
            "bank", "banking", "sparkasse", "volksbank", "paypal", "revolut", "n26", "wise",
            "wallet", "finance", "invest", "trade", "broker", "coinbase", "binance", "crypto",
            "klarna", "venmo", "cashapp", "stripe", "mastercard", "visa", "money", ".pay", "payment",
        ),
        AppCategory.SOCIAL to listOf(
            "facebook", "instagram", "tiktok", "snapchat", "twitter", "com.twitter", "reddit",
            "pinterest", "tumblr", "mastodon", "threads", "bluesky", "linkedin", "vkontakte", "weibo", "quora",
        ),
        AppCategory.COMMUNICATION to listOf(
            "whatsapp", "telegram", "signal", "messenger", "viber", "discord", "slack", "teams",
            "zoom", "skype", "wechat", "kakao", "jp.naver.line", "dialer", "contacts", "mms",
            "messaging", "gmail", "outlook", "protonmail", "email", "com.android.phone",
        ),
        AppCategory.MEDIA to listOf(
            "youtube", "netflix", "spotify", "primevideo", "disney", "hulu", "twitch", "soundcloud",
            "deezer", "tidal", "plex", "kodi", "vlc", "music", "video", "podcast", "hbo", "paramount", "player",
        ),
        AppCategory.GAMES to listOf(
            "game", "games", "unity3d", "gameloft", "supercell", "king.", "miniclip", "roblox",
            "minecraft", "pubg", "genshin", "playrix", "rovio",
        ),
        AppCategory.SHOPPING to listOf(
            "amazon", "ebay", "aliexpress", "etsy", "shein", "temu", "zalando", "otto", "wish",
            "mercado", "shop", "store.", "checkout",
        ),
        AppCategory.MAPS to listOf(
            "maps", "navigation", "navigator", "waze", "here.app", "tomtom", "sygic", "osmand",
            "citymapper", "transit", "geo", "gps",
        ),
        AppCategory.WEATHER to listOf(
            "weather", "forecast", "accuweather", "wetter", "meteo", "windy", "climate",
        ),
        AppCategory.HEALTH to listOf(
            "health", "fitness", "workout", "strava", "runtastic", "fitbit", "garmin",
            "samsunghealth", "googlefit", "meditation", "mindfulness", "calm", "headspace",
        ),
        AppCategory.FOOD to listOf(
            "ubereats", "doordash", "grubhub", "deliveroo", "lieferando", "justeat", "delivery",
            "food", "restaurant", "recipe", "yelp", "zomato", "swiggy",
        ),
        AppCategory.TRAVEL to listOf(
            "travel", "flight", "airline", "booking", "expedia", "airbnb", "hotel", ".trip",
            "uber", "lyft", "bolt", "freenow", "railway", "bahn", "ryanair", "lufthansa", "skyscanner",
        ),
        AppCategory.DATING to listOf(
            "dating", "tinder", "bumble", "hinge", "okcupid", "grindr", "badoo", "match.", "meetic",
        ),
        AppCategory.PHOTO to listOf(
            "camera", "gallery", "photos", "gopro", "snapseed", "lightroom", "vsco", "picsart",
            "canva", "photoeditor",
        ),
        AppCategory.CLOUD to listOf(
            "cloud", "backup", "gdrive", "icloud", "mega.", "pcloud", "nextcloud", "synology",
            "megasync", "storage.",
        ),
        AppCategory.IOT to listOf(
            "smarthome", "smartthings", "smartlife", "tuya", "homeassistant", "philips.lighting",
            ".hue", "mihome", "smarthome", "nest", "ring.", "wyze", "kasa", "tplink", "alexa", "iot",
        ),
        AppCategory.SECURITY to listOf(
            "antivirus", "malwarebytes", "avast", "avg.", "norton", "kaspersky", "bitdefender",
            "eset", "firewall", "password", "bitwarden", "1password", "lastpass", "authenticator",
            "2fa", "openvpn", "wireguard", "vpn", "proxy",
        ),
        AppCategory.BROWSERS to listOf(
            "chrome", "firefox", "browser", "opera", "brave", "duckduckgo", "com.microsoft.emmx",
            "samsungbrowser", "vpn", "proxy", "org.torproject", "wireguard", "dns",
        ),
        AppCategory.PRODUCTIVITY to listOf(
            "docs", "office", "word", "excel", "powerpoint", "notion", "evernote", "keep", "calendar",
            "drive", "dropbox", "onedrive", "trello", "todo", "tasks", "adobe", "acrobat", "pdf", "scanner",
        ),
        AppCategory.EDUCATION to listOf(
            "learn", "education", "study", "school", "university", "science", "wikipedia", "khan",
            "duolingo", "coursera", "udemy", "dictionary", "translate", "math", "physics", "quiz", "course",
        ),
        AppCategory.NEWS to listOf(
            "news", "times", "guardian", ".bbc", "cnn", "reuters", "feedly", "medium", "flipboard", "blog",
        ),
        AppCategory.TOOLS to listOf(
            "tool", "utility", "files", "filemanager", "cleaner", "calculator", "camera", "gallery",
            "flashlight", "weather", "clock", "keyboard", "launcher", "backup", "magisk", "terminal",
            "com.termux", "settings", "root",
        ),
    )

    private val vendorPrefixes: List<Pair<String, String>> = listOf(
        "com.google" to "Google", "com.android" to "Android", "android" to "Android",
        "com.samsung" to "Samsung", "com.sec." to "Samsung", "com.microsoft" to "Microsoft",
        "com.facebook" to "Meta", "com.instagram" to "Meta", "com.whatsapp" to "Meta",
        "com.amazon" to "Amazon", "com.qualcomm" to "Qualcomm", "com.mediatek" to "MediaTek",
        "com.xiaomi" to "Xiaomi", "com.miui" to "Xiaomi", "com.huawei" to "Huawei",
        "com.oppo" to "Oppo", "com.oneplus" to "OnePlus", "com.motorola" to "Motorola",
        "org.mozilla" to "Mozilla", "com.adobe" to "Adobe", "com.spotify" to "Spotify",
    )

    fun categoryOf(pkg: String, label: String, system: Boolean): AppCategory {
        val hay = (pkg + " " + label).lowercase()
        for ((cat, keys) in rules) {
            if (keys.any { hay.contains(it) }) return cat
        }
        // System/daemon/provider services when nothing else matched.
        if (system || pkg.startsWith("com.android.") || pkg.startsWith("android") ||
            pkg.startsWith("com.qualcomm") || pkg.startsWith("com.mediatek") ||
            pkg.contains(".service") || pkg.contains("daemon") || pkg.contains("provider") ||
            pkg.contains("systemui")
        ) return AppCategory.SYSTEM
        return AppCategory.OTHER
    }

    fun vendorOf(pkg: String): String {
        for ((prefix, name) in vendorPrefixes) if (pkg.startsWith(prefix)) return name
        // Fallback: the second package segment, capitalized (com.spotify.x -> Spotify).
        val seg = pkg.split('.').getOrNull(1)?.takeIf { it.isNotBlank() } ?: return "Other"
        return seg.replaceFirstChar { it.uppercase() }
    }
}
