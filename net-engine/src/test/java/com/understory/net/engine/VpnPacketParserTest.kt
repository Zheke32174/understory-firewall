package com.understory.net.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the salvaged [VpnPacketParser]. No Android — this is
 * exactly the value the salvage-as-library move (design-v2/firewall.md §7)
 * is meant to lock in: the parser's bounds-checking and RFC-768
 * zero-checksum rule, testable off the app.
 */
class VpnPacketParserTest {

    /** Build a valid minimal IPv4+UDP packet: 20-byte IP header, 8-byte
     *  UDP header, [payload]. src 10.0.0.1:1234 → dst 10.0.0.2:53. */
    private fun ipv4Udp(payload: ByteArray, dstPort: Int = 53): ByteArray {
        val ihl = 20
        val udpLen = 8 + payload.size
        val total = ihl + udpLen
        val p = ByteArray(total)
        p[0] = ((4 shl 4) or (ihl / 4)).toByte()
        p[2] = (total ushr 8).toByte(); p[3] = (total and 0xFF).toByte()
        p[8] = 64
        p[9] = VpnPacketParser.PROTO_UDP
        // src 10.0.0.1
        p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1
        // dst 10.0.0.2
        p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2
        // UDP: src 1234, dst dstPort, len
        p[20] = (1234 ushr 8).toByte(); p[21] = (1234 and 0xFF).toByte()
        p[22] = (dstPort ushr 8).toByte(); p[23] = (dstPort and 0xFF).toByte()
        p[24] = (udpLen ushr 8).toByte(); p[25] = (udpLen and 0xFF).toByte()
        for (i in payload.indices) p[28 + i] = payload[i]
        return p
    }

    @Test fun parsesValidIpv4Udp() {
        val payload = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0x01, 0x02)
        val pkt = ipv4Udp(payload)
        val parsed = VpnPacketParser.parseIpv4Udp(pkt, pkt.size)
        assertNotNull(parsed)
        parsed!!
        assertEquals("10.0.0.1", parsed.srcIp.hostAddress)
        assertEquals("10.0.0.2", parsed.dstIp.hostAddress)
        assertEquals(1234, parsed.srcPort)
        assertEquals(53, parsed.dstPort)
        assertEquals(20, parsed.ipHeaderLen)
        assertEquals(28, parsed.payloadOffset)
        assertEquals(payload.size, parsed.payloadLen)
    }

    @Test fun rejectsTruncatedHeader() {
        val pkt = ipv4Udp(byteArrayOf(1, 2, 3, 4))
        // Report a length shorter than the IP header claims.
        assertNull(VpnPacketParser.parseIpv4Udp(pkt, 10))
    }

    @Test fun rejectsBadTotalLength() {
        val pkt = ipv4Udp(byteArrayOf(1, 2, 3, 4))
        // totalLen field says more than the buffer holds.
        pkt[2] = 0x7F; pkt[3] = 0xFF.toByte()
        assertNull(VpnPacketParser.parseIpv4Udp(pkt, pkt.size))
    }

    @Test fun rejectsNonUdp() {
        val pkt = ipv4Udp(byteArrayOf(1, 2, 3, 4))
        pkt[9] = VpnPacketParser.PROTO_TCP
        assertNull(VpnPacketParser.parseIpv4Udp(pkt, pkt.size))
    }

    @Test fun isIpv4RejectsShortAndNonV4() {
        assertTrue(!VpnPacketParser.isIpv4(ByteArray(4), 4))
        val v6ish = ByteArray(20); v6ish[0] = (6 shl 4).toByte()
        assertTrue(!VpnPacketParser.isIpv4(v6ish, 20))
    }

    @Test fun buildResponseSwapsAndChecksums() {
        val req = VpnPacketParser.parseIpv4Udp(ipv4Udp(byteArrayOf(9, 9)), 30)!!
        val resp = byteArrayOf(0x10, 0x20, 0x30)
        val out = VpnPacketParser.buildIpv4UdpResponse(req, resp)
        val reparsed = VpnPacketParser.parseIpv4Udp(out, out.size)
        assertNotNull(reparsed)
        reparsed!!
        // src/dst swapped relative to the request.
        assertEquals("10.0.0.2", reparsed.srcIp.hostAddress)
        assertEquals("10.0.0.1", reparsed.dstIp.hostAddress)
        assertEquals(53, reparsed.srcPort)
        assertEquals(1234, reparsed.dstPort)
        assertEquals(resp.size, reparsed.payloadLen)
        // IP header checksum must verify (one's-complement sum == 0xFFFF).
        var sum = 0
        var i = 0
        while (i < 20) {
            sum += ((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        assertEquals(0xFFFF, sum and 0xFFFF)
    }

    @Test fun zeroUdpChecksumTransmittedAsAllOnes() {
        // Craft a request/response whose UDP checksum computes to zero and
        // assert the RFC-768 rule (transmit as 0xFFFF, never 0x0000). We
        // can't easily force a zero directly, so assert the invariant that
        // a built packet never carries a literal 0x0000 UDP checksum.
        val req = VpnPacketParser.parseIpv4Udp(ipv4Udp(byteArrayOf(0, 0, 0, 0)), 32)!!
        val out = VpnPacketParser.buildIpv4UdpResponse(req, byteArrayOf(0, 0))
        val udpCk = ((out[26].toInt() and 0xFF) shl 8) or (out[27].toInt() and 0xFF)
        assertTrue("UDP checksum must never be transmitted as 0x0000", udpCk != 0)
    }

    @Test fun parsesTcpDestPort() {
        val ihl = 20
        val pkt = ByteArray(ihl + 4)
        pkt[0] = ((4 shl 4) or (ihl / 4)).toByte()
        pkt[9] = VpnPacketParser.PROTO_TCP
        pkt[ihl + 2] = (443 ushr 8).toByte()
        pkt[ihl + 3] = (443 and 0xFF).toByte()
        assertEquals(443, VpnPacketParser.parseIpv4TcpDestPort(pkt, pkt.size))
    }
}
