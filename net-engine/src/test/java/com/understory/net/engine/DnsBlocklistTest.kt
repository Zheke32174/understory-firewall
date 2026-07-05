package com.understory.net.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure-JVM tests for the on-device DNS blocklist ([DnsBlocklist]). */
class DnsBlocklistTest {

    @Test fun exactMatchBlocks() {
        val bl = DnsBlocklist.build(sequenceOf("ads.example.com"))
        assertTrue(bl.isBlocked("ads.example.com"))
        assertFalse(bl.isBlocked("example.com"))
    }

    @Test fun parentDomainBlocksSubdomains() {
        val bl = DnsBlocklist.build(sequenceOf("doubleclick.net"))
        assertTrue(bl.isBlocked("doubleclick.net"))
        assertTrue(bl.isBlocked("ad.doubleclick.net"))
        assertTrue(bl.isBlocked("stats.g.doubleclick.net"))
        assertFalse(bl.isBlocked("notdoubleclick.net"))
        assertFalse(bl.isBlocked("doubleclick.net.evil.com"))
    }

    @Test fun allowListWinsOverBlock() {
        val bl = DnsBlocklist.build(
            blockedLines = sequenceOf("example.com"),
            allowLines = sequenceOf("safe.example.com"),
        )
        assertTrue(bl.isBlocked("ads.example.com"))
        assertFalse(bl.isBlocked("safe.example.com"))
        assertFalse(bl.isBlocked("deep.safe.example.com"))
    }

    @Test fun emptyBlocksNothing() {
        val bl = DnsBlocklist.empty()
        assertFalse(bl.isBlocked("anything.com"))
        assertFalse(bl.isBlocked(""))
        assertEquals(0, bl.size)
    }

    @Test fun parsesHostsFormat() {
        assertEquals("ads.example.com", DnsBlocklist.extractDomain("0.0.0.0 ads.example.com"))
        assertEquals("ads.example.com", DnsBlocklist.extractDomain("127.0.0.1  ads.example.com  # comment"))
        assertEquals("ads.example.com", DnsBlocklist.extractDomain("ads.example.com"))
    }

    @Test fun parsesAdblockFormat() {
        assertEquals("tracker.example.com", DnsBlocklist.extractDomain("||tracker.example.com^"))
    }

    @Test fun skipsCommentsAndNonTargets() {
        assertNull(DnsBlocklist.extractDomain("# a comment"))
        assertNull(DnsBlocklist.extractDomain("! adblock comment"))
        assertNull(DnsBlocklist.extractDomain(""))
        assertNull(DnsBlocklist.extractDomain("   "))
        assertNull(DnsBlocklist.extractDomain("127.0.0.1 localhost"))
        assertNull(DnsBlocklist.extractDomain("0.0.0.0 0.0.0.0"))
        assertNull(DnsBlocklist.extractDomain("localhost"))
        // TLD-only / bare word is not a target.
        assertNull(DnsBlocklist.extractDomain("com"))
    }

    @Test fun normalizesCaseAndTrailingDot() {
        assertEquals("ads.example.com", DnsBlocklist.extractDomain("0.0.0.0 Ads.Example.COM."))
        val bl = DnsBlocklist.build(sequenceOf("Ads.Example.Com"))
        assertTrue(bl.isBlocked("ads.example.com"))
        assertTrue(bl.isBlocked("ads.example.com."))
    }

    @Test fun buildCountsUniqueDomains() {
        val bl = DnsBlocklist.build(
            sequenceOf(
                "0.0.0.0 a.com",
                "0.0.0.0 b.com",
                "a.com", // duplicate
                "# comment",
                "",
            ),
        )
        assertEquals(2, bl.size)
    }
}
