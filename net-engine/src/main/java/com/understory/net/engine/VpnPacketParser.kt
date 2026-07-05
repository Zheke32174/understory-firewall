package com.understory.net.engine

import java.net.Inet4Address

/**
 * Minimal IPv4 + UDP packet parser/builder for a userspace tun forwarder.
 *
 * NOTE (updated at S6): this is pure JVM (only `java.net`), bounds-checked,
 * and RFC-768 zero-checksum correct. It is now CALLED by the S6 adblock-DNS
 * tunnel (`firewall/tunnel/DnsFilterTun`) to parse captured DNS queries and
 * build the responses written back to the tun. (Its earlier salvage note said
 * it was dormant/uncalled; that predates S6.) The APP_DROP tunnel flavor still
 * uses a plain drop with no packet parsing.
 *
 * Wire layout parsed:
 *
 *   IPv4 header (RFC 791, 20+ bytes; IHL field gives the actual size):
 *     0    Version(4) | IHL(4)
 *     1    DSCP(6)    | ECN(2)
 *     2-3  Total length
 *     4-5  Identification
 *     6-7  Flags(3)   | Fragment offset(13)
 *     8    TTL
 *     9    Protocol      <-- 17 = UDP, 6 = TCP
 *     10-11 Header checksum
 *     12-15 Source IP
 *     16-19 Destination IP
 *     20+   Options (variable; IHL > 5 means options present)
 *
 *   UDP header (RFC 768, 8 bytes):
 *     0-1 Source port
 *     2-3 Destination port
 *     4-5 Length
 *     6-7 Checksum
 *
 * IPv6 (RFC 8200): not parsed. Tun-level DNS on IPv6 is rare in practice
 * — most app DNS goes via IPv4 even on dual-stack networks because the
 * system resolver picks v4 first.
 */
object VpnPacketParser {

    const val PROTO_TCP: Byte = 6
    const val PROTO_UDP: Byte = 17
    const val DNS_PORT = 53

    /** Parsed view of an IPv4 + L4 packet. Offsets refer to byte
     *  positions in the original buffer the packet was read into. */
    data class Ipv4Udp(
        val srcIp: Inet4Address,
        val dstIp: Inet4Address,
        val srcPort: Int,
        val dstPort: Int,
        val ipHeaderLen: Int,    // bytes
        val totalLen: Int,        // bytes (including IP header)
        val payloadOffset: Int,   // start of UDP payload (DNS query bytes)
        val payloadLen: Int,      // bytes of UDP payload
    )

    /** True iff the buffer starts with a v4 packet (high nibble of byte 0 == 4). */
    fun isIpv4(buf: ByteArray, len: Int): Boolean =
        len >= 20 && (buf[0].toInt() ushr 4) and 0x0F == 4

    /** L4 protocol field. Only valid when [isIpv4] returns true. */
    fun protocol(buf: ByteArray): Byte = buf[9]

    /** Parse an IPv4 + UDP packet. Returns null if the buffer isn't v4,
     *  isn't UDP, or is malformed (truncated header, bad lengths). */
    fun parseIpv4Udp(buf: ByteArray, len: Int): Ipv4Udp? {
        if (!isIpv4(buf, len)) return null
        if (protocol(buf) != PROTO_UDP) return null

        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > len) return null

        val totalLen = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
        if (totalLen > len) return null

        // UDP header starts immediately after the IP header.
        val udpStart = ihl
        if (udpStart + 8 > totalLen) return null

        val srcPort = ((buf[udpStart].toInt() and 0xFF) shl 8) or
            (buf[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((buf[udpStart + 2].toInt() and 0xFF) shl 8) or
            (buf[udpStart + 3].toInt() and 0xFF)
        val udpLen = ((buf[udpStart + 4].toInt() and 0xFF) shl 8) or
            (buf[udpStart + 5].toInt() and 0xFF)
        if (udpLen < 8 || udpStart + udpLen > totalLen) return null

        val src = Inet4Address.getByAddress(buf.copyOfRange(12, 16)) as Inet4Address
        val dst = Inet4Address.getByAddress(buf.copyOfRange(16, 20)) as Inet4Address

        return Ipv4Udp(
            srcIp = src,
            dstIp = dst,
            srcPort = srcPort,
            dstPort = dstPort,
            ipHeaderLen = ihl,
            totalLen = totalLen,
            payloadOffset = udpStart + 8,
            payloadLen = udpLen - 8,
        )
    }

    /** TCP destination port at the canonical offset. Returns null if the
     *  packet isn't IPv4 TCP or is truncated. */
    fun parseIpv4TcpDestPort(buf: ByteArray, len: Int): Int? {
        if (!isIpv4(buf, len)) return null
        if (protocol(buf) != PROTO_TCP) return null
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl + 4 > len) return null
        return ((buf[ihl + 2].toInt() and 0xFF) shl 8) or
            (buf[ihl + 3].toInt() and 0xFF)
    }

    /**
     * Build an IPv4+UDP response packet by swapping src/dst IP and port
     * from a request packet, replacing the UDP payload with the supplied
     * bytes, and recomputing the UDP and IP checksums.
     */
    fun buildIpv4UdpResponse(
        request: Ipv4Udp,
        responsePayload: ByteArray,
    ): ByteArray {
        val ipHeaderLen = 20  // options not preserved on the response
        val udpHeaderLen = 8
        val total = ipHeaderLen + udpHeaderLen + responsePayload.size
        val out = ByteArray(total)

        // ---- IPv4 header ----
        out[0] = ((4 shl 4) or (ipHeaderLen / 4)).toByte()  // Version 4 + IHL 5
        out[1] = 0x00                                          // DSCP/ECN
        out[2] = (total ushr 8).toByte()
        out[3] = (total and 0xFF).toByte()
        out[4] = 0; out[5] = 0                                 // Identification
        out[6] = 0x40; out[7] = 0                              // Flags: Don't Fragment
        out[8] = 64                                            // TTL
        out[9] = PROTO_UDP                                     // Protocol UDP
        out[10] = 0; out[11] = 0                              // checksum filled below
        // Swap src/dst from the request.
        val dstBytes = request.srcIp.address
        val srcBytes = request.dstIp.address
        for (i in 0..3) out[12 + i] = srcBytes[i]
        for (i in 0..3) out[16 + i] = dstBytes[i]

        val ipChecksum = ipv4HeaderChecksum(out, 0, ipHeaderLen)
        out[10] = (ipChecksum ushr 8).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        // ---- UDP header ----
        val udpStart = ipHeaderLen
        out[udpStart] = (request.dstPort ushr 8).toByte()
        out[udpStart + 1] = (request.dstPort and 0xFF).toByte()
        out[udpStart + 2] = (request.srcPort ushr 8).toByte()
        out[udpStart + 3] = (request.srcPort and 0xFF).toByte()
        val udpLen = udpHeaderLen + responsePayload.size
        out[udpStart + 4] = (udpLen ushr 8).toByte()
        out[udpStart + 5] = (udpLen and 0xFF).toByte()
        out[udpStart + 6] = 0; out[udpStart + 7] = 0

        for (i in responsePayload.indices) {
            out[udpStart + udpHeaderLen + i] = responsePayload[i]
        }

        val udpChecksum = udpChecksum(out, ipHeaderLen, udpLen, srcBytes, dstBytes)
        out[udpStart + 6] = (udpChecksum ushr 8).toByte()
        out[udpStart + 7] = (udpChecksum and 0xFF).toByte()

        return out
    }

    // ---------- checksums ----------

    private fun ipv4HeaderChecksum(buf: ByteArray, offset: Int, headerLen: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + headerLen
        while (i < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun udpChecksum(
        buf: ByteArray,
        udpStart: Int,
        udpLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
    ): Int {
        var sum = 0
        // Pseudo-header: src(4) + dst(4) + zero(1) + protocol(1) + udpLen(2)
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
        }
        for (i in 0 until 4 step 2) {
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += PROTO_UDP.toInt() and 0xFF  // upper byte of zero+proto is 0
        sum += udpLen
        var i = udpStart
        val end = udpStart + udpLen
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        // RFC 768: a computed checksum of zero is transmitted as all-ones.
        return if (checksum == 0) 0xFFFF else checksum
    }
}
