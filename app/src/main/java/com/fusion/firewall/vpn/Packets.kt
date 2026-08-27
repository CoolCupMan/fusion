package com.fusion.firewall.vpn

import com.fusion.firewall.data.model.Direction
import com.fusion.firewall.data.model.Transport
import java.net.InetAddress

/** Parsed layer-3/4 view of a single captured IP packet. */
data class ParsedPacket(
    val transport: Transport,
    val protocolNumber: Int,
    val sourceIp: String,
    val destIp: String,
    val sourcePort: Int,
    val destPort: Int,
    val payloadOffset: Int,
    val length: Int,
    val direction: Direction = Direction.OUTBOUND,
)

/**
 * Minimal, allocation-light IP packet parser for IPv4 and IPv6 carrying TCP/UDP.
 * Only the header fields the firewall needs (addresses, ports, protocol) are
 * decoded; the payload is left in place for optional DNS inspection.
 */
object PacketParser {

    const val IPPROTO_ICMP = 1
    const val IPPROTO_TCP = 6
    const val IPPROTO_UDP = 17
    const val IPPROTO_ICMPV6 = 58

    fun parse(buffer: ByteArray, length: Int): ParsedPacket? {
        if (length < 20) return null
        return when (buffer[0].toInt() ushr 4 and 0xF) {
            4 -> parseV4(buffer, length)
            6 -> parseV6(buffer, length)
            else -> null
        }
    }

    private fun parseV4(b: ByteArray, length: Int): ParsedPacket? {
        val ihl = (b[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null
        val protocol = b[9].toInt() and 0xFF
        val src = ipv4(b, 12)
        val dst = ipv4(b, 16)
        return buildL4(b, length, protocol, src, dst, ihl)
    }

    private fun parseV6(b: ByteArray, length: Int): ParsedPacket? {
        if (length < 40) return null
        val nextHeader = b[6].toInt() and 0xFF
        val src = ipv6(b, 8)
        val dst = ipv6(b, 24)
        return buildL4(b, length, nextHeader, src, dst, 40)
    }

    private fun buildL4(
        b: ByteArray,
        length: Int,
        protocol: Int,
        src: String,
        dst: String,
        l4Offset: Int,
    ): ParsedPacket {
        var srcPort = 0
        var dstPort = 0
        var payloadOffset = l4Offset
        val transport = when (protocol) {
            IPPROTO_TCP -> {
                if (length >= l4Offset + 20) {
                    srcPort = port(b, l4Offset)
                    dstPort = port(b, l4Offset + 2)
                    val dataOffset = ((b[l4Offset + 12].toInt() ushr 4) and 0xF) * 4
                    payloadOffset = l4Offset + dataOffset
                }
                Transport.TCP
            }
            IPPROTO_UDP -> {
                if (length >= l4Offset + 8) {
                    srcPort = port(b, l4Offset)
                    dstPort = port(b, l4Offset + 2)
                    payloadOffset = l4Offset + 8
                }
                Transport.UDP
            }
            IPPROTO_ICMP, IPPROTO_ICMPV6 -> Transport.ICMP
            else -> Transport.OTHER
        }
        return ParsedPacket(
            transport = transport,
            protocolNumber = protocol,
            sourceIp = src,
            destIp = dst,
            sourcePort = srcPort,
            destPort = dstPort,
            payloadOffset = payloadOffset,
            length = length,
        )
    }

    private fun port(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun ipv4(b: ByteArray, off: Int): String =
        "${b[off].toInt() and 0xFF}.${b[off + 1].toInt() and 0xFF}." +
            "${b[off + 2].toInt() and 0xFF}.${b[off + 3].toInt() and 0xFF}"

    private fun ipv6(b: ByteArray, off: Int): String =
        runCatching {
            val addr = ByteArray(16)
            System.arraycopy(b, off, addr, 0, 16)
            InetAddress.getByAddress(addr).hostAddress ?: "::"
        }.getOrDefault("::")

    /**
     * Extract the queried domain from a DNS request payload (RFC 1035 QNAME).
     * Returns null for non-DNS or malformed payloads.
     */
    fun dnsQueryName(b: ByteArray, payloadOffset: Int, length: Int): String? {
        // DNS header is 12 bytes; question section follows.
        var pos = payloadOffset + 12
        if (pos >= length) return null
        val sb = StringBuilder()
        var guard = 0
        while (pos < length && guard++ < 64) {
            val len = b[pos].toInt() and 0xFF
            if (len == 0) break
            if (len and 0xC0 != 0) return null // compression pointer — skip
            pos++
            if (pos + len > length) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until len) sb.append((b[pos + i].toInt() and 0xFF).toChar())
            pos += len
        }
        return sb.takeIf { it.isNotEmpty() }?.toString()
    }
}
