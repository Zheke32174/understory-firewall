package com.understory.godwall.chain

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Tests for the HTTP CONNECT tunnel handshake. As with SOCKS5 the sharp edge is
 * stream positioning: the response headers must be consumed EXACTLY, with no
 * read-ahead, or the first bytes of tunnelled payload are lost into a buffer.
 */
class HttpConnectClientTest {

    private fun response(status: String, vararg headers: String): ByteArray =
        (status + "\r\n" + headers.joinToString("") { "$it\r\n" } + "\r\n").toByteArray(Charsets.US_ASCII)

    @Test
    fun `successful connect writes a well formed request`() {
        val input = ByteArrayInputStream(response("HTTP/1.1 200 Connection established"))
        val output = ByteArrayOutputStream()

        HttpConnectClient.connectThrough(input, output, "example.com", 443)

        val sent = output.toString(Charsets.US_ASCII.name())
        assertTrue(sent.startsWith("CONNECT example.com:443 HTTP/1.1\r\n"))
        assertTrue(sent.contains("Host: example.com:443\r\n"))
        assertTrue(sent.endsWith("\r\n\r\n"))
        // No credentials configured means no auth header at all.
        assertFalse(sent.contains("Proxy-Authorization"))
    }

    @Test
    fun `basic auth header is emitted when credentials are configured`() {
        val input = ByteArrayInputStream(response("HTTP/1.1 200 OK"))
        val output = ByteArrayOutputStream()

        HttpConnectClient.connectThrough(input, output, "h", 80, "aladdin", "opensesame")

        val sent = output.toString(Charsets.US_ASCII.name())
        // RFC 7617's own worked example, so the encoding is checked against a known value.
        assertTrue(sent.contains("Proxy-Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n"))
    }

    @Test
    fun `ipv6 literal target is bracketed in the authority`() {
        val input = ByteArrayInputStream(response("HTTP/1.1 200 OK"))
        val output = ByteArrayOutputStream()

        HttpConnectClient.connectThrough(input, output, "2001:db8::1", 853)

        val sent = output.toString(Charsets.US_ASCII.name())
        assertTrue(sent.startsWith("CONNECT [2001:db8::1]:853 HTTP/1.1\r\n"))
    }

    @Test
    fun `payload after the blank line is left intact for the caller`() {
        val payload = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05)   // a TLS ClientHello prefix
        val script = response("HTTP/1.1 200 Connection established", "Proxy-Agent: test") + payload
        val input = ByteArrayInputStream(script)

        HttpConnectClient.connectThrough(input, ByteArrayOutputStream(), "h", 443)

        // Any read-ahead buffering would have swallowed these bytes.
        assertArrayEquals(payload, input.readBytes())
    }

    @Test
    fun `407 is refused loudly rather than tunnelling into nothing`() {
        val script = response("HTTP/1.1 407 Proxy Authentication Required", "Proxy-Authenticate: Basic")
        try {
            HttpConnectClient.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException on 407")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("407"))
        }
    }

    @Test
    fun `503 is refused`() {
        val script = response("HTTP/1.1 503 Service Unavailable")
        try {
            HttpConnectClient.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException on 503")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("503"))
        }
    }

    @Test
    fun `malformed status line is rejected`() {
        val script = "garbage\r\n\r\n".toByteArray()
        try {
            HttpConnectClient.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException on a malformed status line")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("malformed"))
        }
    }

    @Test
    fun `proxy closing before replying is reported, not treated as success`() {
        try {
            HttpConnectClient.connectThrough(
                ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream(), "h", 80,
            )
            fail("expected IOException when the proxy closes immediately")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("closed before replying"))
        }
    }

    @Test
    fun `stream ending inside headers is reported`() {
        val script = "HTTP/1.1 200 OK\r\nX-Partial: yes\r\n".toByteArray() // no terminating blank line
        try {
            HttpConnectClient.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
            fail("expected IOException when headers are truncated")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("ended inside headers"))
        }
    }

    @Test
    fun `a 2xx other than 200 is accepted`() {
        val script = response("HTTP/1.1 201 Created")
        // Any 2xx means the tunnel is open; only non-2xx is a refusal.
        HttpConnectClient.connectThrough(ByteArrayInputStream(script), ByteArrayOutputStream(), "h", 80)
    }
}
