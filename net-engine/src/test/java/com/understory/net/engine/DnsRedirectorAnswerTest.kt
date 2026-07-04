package com.understory.net.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the DNS answer-extraction + rebind hook on
 * [DnsRedirector]. Builds raw RFC 1035 DNS response messages byte-for-byte so
 * the parser's bounds-checking and A/AAAA extraction are locked in off the
 * device. This is engine-mode capability (see the SALVAGE NOTE in
 * DnsRedirector) — the shipping app-drop engine does not invoke it, but the
 * parsing must be correct for a future DNS-redirect forwarder.
 */
class DnsRedirectorAnswerTest {

    /**
     * Build a minimal DNS response: one question for [qname], then one A or
     * AAAA answer per entry in [ips]. Uploads a compression pointer (0xC00C)
     * as each answer's NAME to exercise the pointer path in skipName.
     */
    private fun response(qname: String, ips: List<ByteArray>): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add((v and 0xFF).toByte()) }
        fun u32(v: Long) {
            out.add((v ushr 24).toByte()); out.add((v ushr 16).toByte())
            out.add((v ushr 8).toByte()); out.add((v and 0xFF).toByte())
        }
        // Header
        u16(0x1234)          // ID
        u16(0x8180)          // flags: response, recursion available
        u16(1)               // QDCOUNT
        u16(ips.size)        // ANCOUNT
        u16(0)               // NSCOUNT
        u16(0)               // ARCOUNT
        // Question: QNAME labels, terminating zero, QTYPE, QCLASS
        for (label in qname.split('.')) {
            out.add(label.length.toByte())
            for (ch in label) out.add(ch.code.toByte())
        }
        out.add(0)           // root label
        u16(1)               // QTYPE A
        u16(1)               // QCLASS IN
        // Answers
        for (ip in ips) {
            // NAME = compression pointer to offset 12 (the question's QNAME).
            out.add(0xC0.toByte()); out.add(0x0C.toByte())
            val type = if (ip.size == 4) 1 else 28  // A vs AAAA
            u16(type)        // TYPE
            u16(1)           // CLASS IN
            u32(300L)        // TTL
            u16(ip.size)     // RDLENGTH
            for (b in ip) out.add(b)  // RDATA
        }
        return out.toByteArray()
    }

    private fun v4(a: Int, b: Int, c: Int, d: Int) =
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    @Test fun extractsSingleAAnswer() {
        val msg = response("example.com", listOf(v4(93, 184, 216, 34)))
        val ips = DnsRedirector.extractAnswerIps(msg)
        assertEquals(1, ips.size)
        assertEquals("93.184.216.34", ips[0].hostAddress)
    }

    @Test fun extractsMultipleAnswersIncludingAaaa() {
        val aaaa = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[15] = 1 }
        val msg = response("example.com", listOf(v4(1, 2, 3, 4), aaaa))
        val ips = DnsRedirector.extractAnswerIps(msg)
        assertEquals(2, ips.size)
        assertEquals("1.2.3.4", ips[0].hostAddress)
    }

    @Test fun malformedTruncatedMessageYieldsEmpty() {
        val msg = response("example.com", listOf(v4(1, 2, 3, 4)))
        // Chop it mid-answer — parser must return what it has (empty) not throw.
        val truncated = msg.copyOfRange(0, msg.size - 2)
        val ips = DnsRedirector.extractAnswerIps(truncated)
        // With RDLENGTH extending past the buffer, the answer is dropped.
        assertTrue(ips.isEmpty())
    }

    @Test fun shortBufferYieldsEmpty() {
        assertTrue(DnsRedirector.extractAnswerIps(ByteArray(4)).isEmpty())
        assertTrue(DnsRedirector.extractAnswerIps(ByteArray(0)).isEmpty())
    }

    @Test fun rebindHookFlagsPublicNameResolvingToPrivate() {
        val msg = response("evil.example.com", listOf(v4(127, 0, 0, 1)))
        val verdict = DnsRedirector.rebindRiskInResponse("evil.example.com", msg)
        assertTrue(verdict.rebindRisk)
        assertEquals(1, verdict.reasons.size)
    }

    @Test fun rebindHookPassesPublicNameResolvingToPublic() {
        val msg = response("example.com", listOf(v4(93, 184, 216, 34)))
        val verdict = DnsRedirector.rebindRiskInResponse("example.com", msg)
        assertFalse(verdict.rebindRisk)
    }

    @Test fun rebindHookAllowsLocalNameResolvingToPrivate() {
        val msg = response("printer.local", listOf(v4(192, 168, 1, 50)))
        val verdict = DnsRedirector.rebindRiskInResponse("printer.local", msg)
        assertFalse(verdict.rebindRisk)
    }
}
