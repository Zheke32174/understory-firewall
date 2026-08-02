package com.understory.godwall.ward

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EnforcementSelectionTest {

    private fun probe(b: EnforcementBackend, available: Boolean) =
        BackendProbe(b, available, if (available) "probed OK" else "not available")

    @Test
    fun `auto-select takes the strongest available backend`() {
        val probes = listOf(
            probe(EnforcementBackend.IPTABLES, false),
            probe(EnforcementBackend.CONNECTIVITY_MANAGER, true),
            probe(EnforcementBackend.NETWORK_POLICY_MANAGER, true),
            probe(EnforcementBackend.VPN, true),
            probe(EnforcementBackend.PROXY, false),
        )
        val s = Enforcement.select(probes, manual = null)
        assertEquals(EnforcementBackend.CONNECTIVITY_MANAGER, s.chosen)
        assertFalse(s.manualOverridden)
    }

    @Test
    fun `iptables outranks everything when it is there`() {
        val probes = EnforcementBackend.entries.map { probe(it, true) }
        assertEquals(EnforcementBackend.IPTABLES, Enforcement.select(probes, null).chosen)
    }

    @Test
    fun `a pin that is available is honoured`() {
        val probes = listOf(
            probe(EnforcementBackend.IPTABLES, true),
            probe(EnforcementBackend.VPN, true),
        )
        val s = Enforcement.select(probes, manual = EnforcementBackend.VPN)
        assertEquals(EnforcementBackend.VPN, s.chosen)
        assertFalse(s.manualOverridden)
    }

    @Test
    fun `a pin that is unavailable falls back AND is reported as not in force`() {
        val probes = listOf(
            probe(EnforcementBackend.IPTABLES, false),
            probe(EnforcementBackend.VPN, true),
        )
        val s = Enforcement.select(probes, manual = EnforcementBackend.IPTABLES)
        assertEquals(EnforcementBackend.VPN, s.chosen)
        assertTrue(s.manualOverridden)
        assertEquals(EnforcementBackend.IPTABLES, s.manual)
    }

    @Test
    fun `nothing available means nothing chosen — never a default that does not run`() {
        val probes = EnforcementBackend.entries.map { probe(it, false) }
        assertNull(Enforcement.select(probes, null).chosen)
    }

    @Test
    fun `the preference order covers every backend exactly once`() {
        assertEquals(EnforcementBackend.entries.size, Enforcement.PREFERENCE_ORDER.size)
        assertEquals(EnforcementBackend.entries.toSet(), Enforcement.PREFERENCE_ORDER.toSet())
    }
}
