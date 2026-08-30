package com.fusion.firewall.net

/**
 * Fast, thread-safe decision engine for the DNS filter. Holds the active set of
 * blocked domains (from imported block lists + custom entries), a whitelist that
 * always wins, and the set of app uids that are fully blocked (their every
 * lookup is sinkholed). Matching is suffix-based so blocking `example.com` also
 * blocks `ads.example.com`.
 */
class DomainBlocker {

    @Volatile private var blocked: Set<String> = emptySet()
    @Volatile private var whitelist: Set<String> = emptySet()
    @Volatile private var blockedUids: Set<Int> = emptySet()

    fun update(blocked: Set<String>, whitelist: Set<String>, blockedUids: Set<Int>) {
        this.blocked = blocked
        this.whitelist = whitelist
        this.blockedUids = blockedUids
    }

    val blockedDomainCount: Int get() = blocked.size

    fun isBlockedUid(uid: Int): Boolean = uid > 0 && uid in blockedUids

    /** True when the domain (or a parent) is on the block list, or the app is blocked. */
    fun isBlocked(domain: String, uid: Int): Boolean {
        if (uid > 0 && uid in blockedUids) return true
        val d = domain.lowercase().trimEnd('.')
        if (d.isEmpty()) return false
        if (matchesSuffix(d, whitelist)) return false
        return matchesSuffix(d, blocked)
    }

    private fun matchesSuffix(domain: String, set: Set<String>): Boolean {
        if (set.isEmpty()) return false
        var s = domain
        while (true) {
            if (s in set) return true
            val dot = s.indexOf('.')
            if (dot < 0) return false
            s = s.substring(dot + 1)
        }
    }
}
