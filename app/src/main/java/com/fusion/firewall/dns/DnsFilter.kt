package com.fusion.firewall.dns

/**
 * Minimal DNS message helpers for the filter: parse the queried name/type from a
 * request payload, and synthesize an NXDOMAIN response to sinkhole a blocked
 * domain (the app then treats the name as non-existent and the connection never
 * happens).
 */
object DnsFilter {

    data class Query(val name: String, val questionEnd: Int, val qtype: Int)

    /** Parse the first question. [len] is the DNS payload length. */
    fun parseQuery(p: ByteArray, len: Int): Query? {
        if (len < 12) return null
        val qd = ((p[4].toInt() and 0xFF) shl 8) or (p[5].toInt() and 0xFF)
        if (qd < 1) return null
        var pos = 12
        val sb = StringBuilder()
        var guard = 0
        while (pos < len && guard++ < 128) {
            val l = p[pos].toInt() and 0xFF
            if (l == 0) { pos++; break }
            if (l and 0xC0 != 0) return null // compression not expected in a question
            pos++
            if (pos + l > len) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until l) sb.append((p[pos + i].toInt() and 0xFF).toChar())
            pos += l
        }
        if (pos + 4 > len) return null
        val qtype = ((p[pos].toInt() and 0xFF) shl 8) or (p[pos + 1].toInt() and 0xFF)
        return Query(sb.toString(), pos + 4, qtype)
    }

    /** Build an NXDOMAIN response echoing the request's id + question. */
    fun buildNxdomain(request: ByteArray, questionEnd: Int): ByteArray {
        val out = request.copyOf(questionEnd)
        val rd = request[2].toInt() and 0x01
        out[2] = (0x80 or rd).toByte()   // QR=1, opcode=0, RD mirrored
        out[3] = 0x83.toByte()           // RA=1, RCODE=3 (NXDOMAIN)
        // ANCOUNT / NSCOUNT / ARCOUNT = 0 (drop any EDNS/OPT that followed).
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }
}
