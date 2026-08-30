package com.fusion.firewall.dns

/** Builds an IPv4/UDP packet for writing DNS responses back into the tun. */
object Ipv4 {

    /**
     * @param srcIp 4-byte source address (the DNS server the app queried)
     * @param dstIp 4-byte destination (the app's tun address)
     */
    fun buildUdp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val total = 20 + 8 + payload.size
        val b = ByteArray(total)

        // --- IPv4 header ---
        b[0] = 0x45                 // version 4, IHL 5
        b[2] = (total ushr 8).toByte(); b[3] = total.toByte()
        b[8] = 64                   // TTL
        b[9] = 17                   // protocol UDP
        System.arraycopy(srcIp, 0, b, 12, 4)
        System.arraycopy(dstIp, 0, b, 16, 4)
        val ipck = checksum(b, 0, 20)
        b[10] = (ipck ushr 8).toByte(); b[11] = ipck.toByte()

        // --- UDP header (checksum 0 = not computed, valid for IPv4) ---
        val u = 20
        b[u] = (srcPort ushr 8).toByte(); b[u + 1] = srcPort.toByte()
        b[u + 2] = (dstPort ushr 8).toByte(); b[u + 3] = dstPort.toByte()
        val ulen = 8 + payload.size
        b[u + 4] = (ulen ushr 8).toByte(); b[u + 5] = ulen.toByte()
        System.arraycopy(payload, 0, b, u + 8, payload.size)
        return b
    }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        var remaining = len
        while (remaining > 1) {
            sum += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2; remaining -= 2
        }
        if (remaining > 0) sum += ((b[i].toInt() and 0xFF) shl 8).toLong()
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}
