package com.understory.net.engine

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the DNS *query* parser + blocked-answer synthesizer
 * ([DnsMessage]), the query-side counterpart to DnsRedirectorAnswerTest. Builds
 * raw RFC 1035 query messages byte-for-byte so the S6 tunnel's question
 * extraction and sinkhole crafting are locked in off the device.
 */
class DnsMessageTest {

    /** Build a minimal single-question DNS query for [qname] with [qtype]. */
    private fun query(qname: String, qtype: Int = DnsMessage.TYPE_A, rd: Boolean = true): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add((v and 0xFF).toByte()) }
        u16(0xABCD)                       // ID
        u16(if (rd) 0x0100 else 0x0000)   // flags: RD bit
        u16(1)                            // QDCOUNT
        u16(0); u16(0); u16(0)            // AN/NS/AR
        for (label in qname.split('.')) {
            out.add(label.length.toByte())
            for (ch in label) out.add(ch.code.toByte())
        }
        out.add(0)                        // root
        u16(qtype)                        // QTYPE
        u16(1)                            // QCLASS IN
        return out.toByteArray()
    }

    @Test fun parsesSimpleQuestion() {
        val q = DnsMessage.parseFirstQuestion(query("ads.example.com"))!!
        assertEquals("ads.example.com", q.name)
        assertEquals(DnsMessage.TYPE_A, q.qtype)
        assertEquals(1, q.qclass)
    }

    @Test fun lowercasesName() {
        val q = DnsMessage.parseFirstQuestion(query("Ads.EXAMPLE.Com"))!!
        assertEquals("ads.example.com", q.name)
    }

    @Test fun rejectsTruncated() {
        val full = query("example.com")
        // Cut off mid-QNAME.
        assertNull(DnsMessage.parseFirstQuestion(full.copyOf(14)))
        // Shorter than a header.
        assertNull(DnsMessage.parseFirstQuestion(ByteArray(8)))
    }

    @Test fun rejectsPointerInQuestion() {
        val bytes = query("example.com")
        // Overwrite the first label length with a pointer marker (0xC0).
        bytes[12] = 0xC0.toByte()
        assertNull(DnsMessage.parseFirstQuestion(bytes))
    }

    @Test fun nxdomainResponseEchoesQuestionAndSetsRcode3() {
        val q = query("tracker.example.com")
        val resp = DnsMessage.buildBlockedResponse(q, DnsMessage.BlockAnswer.NXDOMAIN)!!
        // QR=1
        assertTrue((resp[2].toInt() and 0x80) != 0)
        // RCODE=3 (low nibble of byte 3)
        assertEquals(3, resp[3].toInt() and 0x0F)
        // RA=1
        assertTrue((resp[3].toInt() and 0x80) != 0)
        // ANCOUNT = 0
        assertEquals(0, ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF))
        // ID preserved.
        assertArrayEquals(q.copyOf(2), resp.copyOf(2))
        // Question section echoed verbatim (header+question length == whole resp).
        assertEquals(q.size, resp.size)
    }

    @Test fun zeroIpResponseHasOneAAnswer() {
        val q = query("ads.example.com", DnsMessage.TYPE_A)
        val resp = DnsMessage.buildBlockedResponse(q, DnsMessage.BlockAnswer.ZERO_IP)!!
        // RCODE=0 (NOERROR)
        assertEquals(0, resp[3].toInt() and 0x0F)
        // ANCOUNT = 1
        assertEquals(1, ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF))
        // The A answer's RDATA is 0.0.0.0 — the last 4 bytes of the message.
        val rdata = resp.copyOfRange(resp.size - 4, resp.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), rdata)
        // Extractable back through the answer parser as 0.0.0.0.
        val answerOnly = resp.copyOfRange(0, resp.size)
        val ips = DnsRedirector.extractAnswerIps(answerOnly)
        assertEquals(1, ips.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), ips[0].address)
    }

    @Test fun zeroIpAaaaGivesSixteenZeroBytes() {
        val q = query("ads.example.com", DnsMessage.TYPE_AAAA)
        val resp = DnsMessage.buildBlockedResponse(q, DnsMessage.BlockAnswer.ZERO_IP)!!
        assertEquals(1, ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF))
        val rdata = resp.copyOfRange(resp.size - 16, resp.size)
        assertArrayEquals(ByteArray(16), rdata)
    }
}
