package com.understory.net.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * Pure-JVM tests for [RebindClassifier]. No Android — the classifier is the
 * heart of both the on-demand companion auditor and the opt-in engine's
 * answer-drop path, so its predicate is locked in here off the device.
 *
 * All addresses are built from literal bytes via [InetAddress.getByAddress] so
 * no test ever performs a real DNS lookup.
 */
class RebindClassifierTest {

    private fun v4(a: Int, b: Int, c: Int, d: Int): InetAddress =
        InetAddress.getByAddress(byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte()))

    private fun v6(bytes: ByteArray): InetAddress = InetAddress.getByAddress(bytes)

    @Test fun publicToPublicIsSafe() {
        val v = RebindClassifier.classify("example.com", listOf(v4(93, 184, 216, 34)))
        assertFalse(v.rebindRisk)
        assertTrue(v.reasons.isEmpty())
    }

    @Test fun publicToLoopbackIsRisk() {
        val v = RebindClassifier.classify("evil.example.com", listOf(v4(127, 0, 0, 1)))
        assertTrue(v.rebindRisk)
        assertEquals(1, v.reasons.size)
        assertTrue(v.reasons[0].contains("127.0.0.1"))
    }

    @Test fun publicToRfc1918TenIsRisk() {
        val v = RebindClassifier.classify("cdn.example.net", listOf(v4(10, 1, 2, 3)))
        assertTrue(v.rebindRisk)
    }

    @Test fun publicTo192_168IsRisk() {
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(192, 168, 1, 1))).rebindRisk)
    }

    @Test fun publicTo172_16IsRisk() {
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(172, 16, 0, 5))).rebindRisk)
        // 172.15 and 172.32 are OUTSIDE the /12 — public.
        assertFalse(RebindClassifier.classify("x.example.org", listOf(v4(172, 15, 0, 5))).rebindRisk)
        assertFalse(RebindClassifier.classify("x.example.org", listOf(v4(172, 32, 0, 5))).rebindRisk)
    }

    @Test fun cgnatIsRisk() {
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(100, 64, 0, 1))).rebindRisk)
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(100, 127, 255, 255))).rebindRisk)
        // 100.63 and 100.128 are outside 100.64.0.0/10.
        assertFalse(RebindClassifier.classify("x.example.org", listOf(v4(100, 63, 0, 1))).rebindRisk)
        assertFalse(RebindClassifier.classify("x.example.org", listOf(v4(100, 128, 0, 1))).rebindRisk)
    }

    @Test fun testNetsAreRisk() {
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(192, 0, 2, 7))).rebindRisk)
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(198, 51, 100, 7))).rebindRisk)
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(203, 0, 113, 7))).rebindRisk)
    }

    @Test fun linkLocalAndZeroNetAreRisk() {
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(169, 254, 1, 1))).rebindRisk)
        assertTrue(RebindClassifier.classify("x.example.org", listOf(v4(0, 0, 0, 0))).rebindRisk)
    }

    @Test fun localNameToPrivateIsSafe() {
        // *.local / *.lan intranet names are allowed to resolve to private IPs.
        assertFalse(RebindClassifier.classify("printer.local", listOf(v4(192, 168, 1, 50))).rebindRisk)
        assertFalse(RebindClassifier.classify("nas.lan", listOf(v4(10, 0, 0, 9))).rebindRisk)
        assertFalse(RebindClassifier.classify("host.internal", listOf(v4(172, 16, 5, 5))).rebindRisk)
        assertFalse(RebindClassifier.classify("gw.home.arpa", listOf(v4(192, 168, 0, 1))).rebindRisk)
        assertFalse(RebindClassifier.classify("localhost", listOf(v4(127, 0, 0, 1))).rebindRisk)
    }

    @Test fun literalIpHostIsSafe() {
        // A literal-IP "host" is not a DNS name to rebind; treat as local.
        assertFalse(RebindClassifier.classify("192.168.1.1", listOf(v4(192, 168, 1, 1))).rebindRisk)
        assertFalse(RebindClassifier.classify("10.0.0.1", listOf(v4(10, 0, 0, 1))).rebindRisk)
        assertFalse(RebindClassifier.classify("::1", listOf(v6(loopback6()))).rebindRisk)
    }

    @Test fun ipv6UlaIsRisk() {
        // fc00::/7 unique-local (fd00::1 shown here) for a public name.
        val fd00 = ByteArray(16).also { it[0] = 0xFD.toByte(); it[15] = 1 }
        assertTrue(RebindClassifier.classify("evil.example.com", listOf(v6(fd00))).rebindRisk)
        // fe80:: link-local is also a risk.
        val fe80 = ByteArray(16).also { it[0] = 0xFE.toByte(); it[1] = 0x80.toByte(); it[15] = 1 }
        assertTrue(RebindClassifier.classify("evil.example.com", listOf(v6(fe80))).rebindRisk)
    }

    @Test fun publicIpv6IsSafe() {
        // 2606:4700:4700::1111 (a public resolver) — not reserved.
        val pub = byteArrayOf(
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        )
        assertFalse(RebindClassifier.classify("dns.example.com", listOf(v6(pub))).rebindRisk)
    }

    @Test fun ipv4MappedPrivateIsRisk() {
        // ::ffff:10.1.2.3 — an IPv4-mapped v6 answer wrapping a private v4.
        val mapped = ByteArray(16).also {
            it[10] = 0xFF.toByte(); it[11] = 0xFF.toByte()
            it[12] = 10; it[13] = 1; it[14] = 2; it[15] = 3
        }
        assertTrue(RebindClassifier.classify("evil.example.com", listOf(v6(mapped))).rebindRisk)
        // ::ffff:93.184.216.34 — mapped public v4 is safe.
        val mappedPub = ByteArray(16).also {
            it[10] = 0xFF.toByte(); it[11] = 0xFF.toByte()
            it[12] = 93.toByte(); it[13] = 184.toByte(); it[14] = 216.toByte(); it[15] = 34
        }
        assertFalse(RebindClassifier.classify("cdn.example.com", listOf(v6(mappedPub))).rebindRisk)
    }

    @Test fun mixedAnswersFlagOnlyTheReservedOne() {
        val v = RebindClassifier.classify(
            "evil.example.com",
            listOf(v4(93, 184, 216, 34), v4(127, 0, 0, 1)),
        )
        assertTrue(v.rebindRisk)
        assertEquals(1, v.reasons.size)
    }

    private fun loopback6(): ByteArray = ByteArray(16).also { it[15] = 1 }
}
