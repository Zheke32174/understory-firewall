package com.understory.godwall.chain

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Byte-level tests for the SOCKS5 handshake. These matter more than usual: a
 * one-byte framing mistake does not fail loudly, it DESYNCS the stream, and the
 * caller then sends payload into a misaligned tunnel. The reply-consumption tests
 * below are specifically guarding that class of bug.
 */
class Socks5ClientTest {

    /** Server script: greeting reply (no-auth) + a successful CONNECT reply with an IPv4 bind. */
    private fun okReplyIpv4(): ByteArray = byteArrayOf(
        0x05, 0x00,                                     // greeting: version 5, method 0 (no auth)
        0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00, // reply: succeeded, ATYP=IPv4, 0.0.0.0:0
    )

    @Test
    fun `no-auth connect to domain writes correct greeting and request`() {
        val input = ByteArrayInputStream(okReplyIpv4())
        val output = ByteArrayOutputStream()

        Socks5Client.connectThrough(input, output, "example.com", 443)

        val sent = output.toByteArray()
        // Greeting: VER=5, NMETHODS=1, METHOD=0x00
        assertArrayEquals(byteArrayOf(0x05, 0x01, 0x00), sent.copyOfRange(0, 3))
        // Request: VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN, LEN=11, "example.com", port 443
        val expectedRequest = byteArrayOf(0x05, 0x01, 0x00, 0x03, 11) +
            "example.com".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0x01, 0xBB.toByte())            // 443 = 0x01BB, big endian
        assertArrayEquals(expectedRequest, sent.copyOfRange(3, sent.size))
    }

    @Test
    fun `literal IPv4 target is sent as ATYP IPv4 and never resolved`() {
        val input = ByteArrayInputStream(okReplyIpv4())
        val output = ByteArrayOutputStream()

        Socks5Client.connectThrough(input, output, "1.1.1.1", 853)

        val sent = output.toByteArray()
        val request = sent.copyOfRange(3, sent.size)
        val expected = byteArrayOf(0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1) +
            byteArrayOf(0x03, 0x55)                     // 853 = 0x0355
        assertArrayEquals(expected, request)
    }

    @Test
    fun `username password auth is negotiated and accepted`() {
        val script = byteArrayOf(
            0x05, 0x02,                                 // greeting reply: choose user/pass
            0x01, 0x00,                                 // auth reply: version 1, status 0 (ok)
            0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,   // connect reply: succeeded
        )
        val input = ByteArrayInputStream(script)
        val output = ByteArrayOutputStream()

        Socks5Client.connectThrough(input, output, "h", 80, "user", "pw")

        val sent = output.toByteArray()
        // Greeting offers BOTH methods when credentials are configured.
        assertArrayEquals(byteArrayOf(0x05, 0x02, 0x00, 0x02), sent.copyOfRange(0, 4))
        // Auth: VER=1, ULEN=4,"user", PLEN=2,"pw"
        val auth = byteArrayOf(0x01, 4) + "user".toByteArray() + byteArrayOf(2) + "pw".toByteArray()
        assertArrayEquals(auth, sent.copyOfRange(4, 4 + auth.size))
    }

    @Test
    fun `rejected credentials throw rather than continuing`() {
        val script = byteArrayOf(
            0x05, 0x02,
            0x01, 0x01, // auth status 1 = failure
        )
        try {
            Socks5Client.connectThrough(
                ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80, "u", "bad",
            )
            fail("expected IOException on rejected credentials")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("rejected"))
        }
    }

    @Test
    fun `proxy demanding auth with no credentials configured throws`() {
        val script = byteArrayOf(0x05, 0x02)
        try {
            Socks5Client.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException when proxy demands auth we cannot provide")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("no credentials"))
        }
    }

    @Test
    fun `no acceptable methods throws`() {
        val script = byteArrayOf(0x05, 0xFF.toByte())
        try {
            Socks5Client.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException when proxy rejects all methods")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("rejected all"))
        }
    }

    @Test
    fun `connect refusal surfaces the RFC reply text`() {
        val script = byteArrayOf(
            0x05, 0x00,
            0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0,   // REP=5 connection refused
        )
        try {
            Socks5Client.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException on CONNECT refusal")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("connection refused"))
        }
    }

    // --- The desync guards: the bound address must be fully consumed, whatever its type ---

    @Test
    fun `ipv6 bound address in reply is fully consumed so payload starts clean`() {
        val payload = "PAYLOAD".toByteArray()
        val script = byteArrayOf(0x05, 0x00) +
            byteArrayOf(0x05, 0x00, 0x00, 0x04) + ByteArray(16) + byteArrayOf(0x00, 0x50) +
            payload
        val input = ByteArrayInputStream(script)

        Socks5Client.connectThrough(input, ByteArrayOutputStream(), "h", 80)

        assertArrayEquals(payload, input.readBytes())
    }

    @Test
    fun `domain bound address in reply is fully consumed so payload starts clean`() {
        val payload = "NEXTHOP".toByteArray()
        val bnd = "proxy.internal".toByteArray(Charsets.US_ASCII)
        val script = byteArrayOf(0x05, 0x00) +
            byteArrayOf(0x05, 0x00, 0x00, 0x03, bnd.size.toByte()) + bnd + byteArrayOf(0x1F, 0x90.toByte()) +
            payload
        val input = ByteArrayInputStream(script)

        Socks5Client.connectThrough(input, ByteArrayOutputStream(), "h", 80)

        // If the domain length byte were mishandled, this would return shifted bytes.
        assertArrayEquals(payload, input.readBytes())
    }

    @Test
    fun `ipv4 bound address in reply is fully consumed so payload starts clean`() {
        val payload = byteArrayOf(0x16, 0x03, 0x01) // looks like a TLS record — the realistic next write
        val script = okReplyIpv4() + payload
        val input = ByteArrayInputStream(script)

        Socks5Client.connectThrough(input, ByteArrayOutputStream(), "h", 80)

        assertArrayEquals(payload, input.readBytes())
    }

    @Test
    fun `oversized hostname is refused instead of being truncated`() {
        val tooLong = "a".repeat(256)
        try {
            Socks5Client.connectThrough(
                ByteArrayInputStream(okReplyIpv4()), ByteArrayOutputStream(), tooLong, 80,
            )
            fail("expected IOException for a hostname longer than the SOCKS5 length field")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("length out of range"))
        }
    }

    @Test
    fun `non-canonical dotted quad is treated as a domain not an IP`() {
        val input = ByteArrayInputStream(okReplyIpv4())
        val output = ByteArrayOutputStream()

        // "01.1.1.1" is not a canonical literal; sending it as IPv4 would silently
        // change the destination, so it must go out as a domain for the proxy to judge.
        Socks5Client.connectThrough(input, output, "01.1.1.1", 80)

        val atyp = output.toByteArray()[6]
        assertEquals(0x03.toByte(), atyp)
    }
}
