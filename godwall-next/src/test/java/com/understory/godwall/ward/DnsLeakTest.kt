package com.understory.godwall.ward

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsLeakTest {

    private val ours = "203.0.113.53"

    @Test
    fun `not armed is not a leak — there is nothing to leak from`() {
        val r = DnsLeak.classify(armed = false, servers = listOf("8.8.8.8"), expected = ours, excludedApps = 0)
        assertEquals(DnsLeak.Verdict.NOT_ARMED, r.verdict)
    }

    @Test
    fun `armed with only our resolver is OK`() {
        val r = DnsLeak.classify(armed = true, servers = listOf(ours), expected = ours, excludedApps = 0)
        assertEquals(DnsLeak.Verdict.OK, r.verdict)
        assertTrue(r.ok)
    }

    @Test
    fun `armed with a foreign resolver is a leak, and the address is named`() {
        val r = DnsLeak.classify(
            armed = true,
            servers = listOf(ours, "8.8.8.8"),
            expected = ours,
            excludedApps = 0,
        )
        assertEquals(DnsLeak.Verdict.LEAK, r.verdict)
        assertTrue(r.detail.contains("8.8.8.8"))
    }

    @Test
    fun `no resolver reported is UNKNOWN, never OK`() {
        val r = DnsLeak.classify(armed = true, servers = emptyList(), expected = ours, excludedApps = 0)
        assertEquals(DnsLeak.Verdict.UNKNOWN, r.verdict)
    }

    @Test
    fun `deliberately excluded apps are declared rather than hidden inside an OK`() {
        val r = DnsLeak.classify(armed = true, servers = listOf(ours), expected = ours, excludedApps = 3)
        assertEquals(DnsLeak.Verdict.OK, r.verdict)
        assertTrue(r.detail.contains("3 app"))
    }
}
