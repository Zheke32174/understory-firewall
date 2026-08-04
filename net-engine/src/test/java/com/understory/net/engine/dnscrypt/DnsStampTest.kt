package com.understory.net.engine.dnscrypt

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * Parser round-trips for the `sdns://` stamp format the InviZible/dnscrypt-proxy
 * resolver lists use. Stamps are constructed from known bytes (rather than pasted
 * base64 we can't independently verify), so a field-level regression fails here.
 */
class DnsStampTest {

    private fun sdns(bytes: ByteArray) =
        "sdns://" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun ByteArrayOutputStream.lp(b: ByteArray) { write(b.size); write(b) }
    private fun ByteArrayOutputStream.lp(s: String) = lp(s.toByteArray())
    private fun ByteArrayOutputStream.u64(v: Long) { for (k in 0 until 8) write(((v ushr (8 * k)) and 0xFF).toInt()) }

    @Test fun dnscrypt_stamp() {
        val pk = ByteArray(32) { (it + 1).toByte() }
        val bytes = ByteArrayOutputStream().apply {
            write(0x01); u64(0x3L); lp("10.0.0.1:5353"); lp(pk); lp("2.dnscrypt-cert.example.com")
        }.toByteArray()
        val s = DnsStamp.parse(sdns(bytes))!!
        assertEquals(DnsStamp.Proto.DNSCRYPT, s.proto)
        assertTrue(s.dnssec && s.noLogs && !s.noFilter)
        assertEquals("10.0.0.1", s.addressIp())
        assertEquals(5353, s.addressPort(443))
        assertArrayEquals32(pk, s.publicKey)
        assertEquals("2.dnscrypt-cert.example.com", s.providerName)
    }

    @Test fun doh_stamp() {
        val hash = ByteArray(32) { 0xAA.toByte() }
        val bytes = ByteArrayOutputStream().apply {
            write(0x02); u64(0x4L); lp("1.1.1.1"); write(hash.size); write(hash)
            lp("cloudflare-dns.com"); lp("/dns-query")
        }.toByteArray()
        val s = DnsStamp.parse(sdns(bytes))!!
        assertEquals(DnsStamp.Proto.DOH, s.proto)
        assertEquals("cloudflare-dns.com", s.hostname)
        assertEquals("/dns-query", s.path)
        assertEquals(1, s.hashes.size)
        assertTrue(s.noFilter)
    }

    @Test fun relay_stamp() {
        val bytes = ByteArrayOutputStream().apply { write(0x81); lp("9.9.9.9:443") }.toByteArray()
        val s = DnsStamp.parse(sdns(bytes))!!
        assertEquals(DnsStamp.Proto.DNSCRYPT_RELAY, s.proto)
        assertEquals("9.9.9.9:443", s.address)
    }

    @Test fun malformed_is_null_never_throws() {
        assertNull(DnsStamp.parse("sdns://!!!not-base64!!!"))
        assertNull(DnsStamp.parse(""))
        assertNull(DnsStamp.parse("http://example.com"))
        assertNull(DnsStamp.parse("sdns://AQ")) // truncated body
    }

    private fun assertArrayEquals32(a: ByteArray, b: ByteArray) {
        assertEquals(a.size, b.size)
        for (i in a.indices) assertEquals(a[i], b[i])
    }
}
