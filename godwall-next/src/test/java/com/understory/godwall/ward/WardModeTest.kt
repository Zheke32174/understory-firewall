package com.understory.godwall.ward

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The mode table is what the engine reads on every DNS packet and on every arm, so it is worth
 * pinning: a silent flip of one boolean here is a mode that claims a tier it does not run.
 */
class WardModeTest {

    @Test
    fun `default is the donor's default — DNS plus firewall`() {
        assertEquals(WardMode.DNS_FIREWALL, WardModeStore.DEFAULT)
        assertTrue(WardMode.DNS_FIREWALL.filtersDns)
        assertTrue(WardMode.DNS_FIREWALL.enforcesFirewall)
        assertFalse(WardMode.DNS_FIREWALL.runsTailnet)
    }

    @Test
    fun `each mode names exactly the tiers it turns on`() {
        assertEquals(listOf(WardTier.DNS), WardMode.DNS_ONLY.tiers())
        assertEquals(listOf(WardTier.FIREWALL), WardMode.FIREWALL_ONLY.tiers())
        assertEquals(listOf(WardTier.DNS, WardTier.FIREWALL), WardMode.DNS_FIREWALL.tiers())
        assertEquals(listOf(WardTier.TAILNET), WardMode.TAILNET_ONLY.tiers())
        assertEquals(
            listOf(WardTier.DNS, WardTier.FIREWALL, WardTier.TAILNET),
            WardMode.FULL_STACK.tiers(),
        )
    }

    @Test
    fun `the DNS tier is never reported unmet — it needs no privilege and no payload`() {
        val unmet = WardMode.FULL_STACK.unmet(firewallAvailable = false, tailnetAvailable = false)
        assertFalse(WardTier.DNS in unmet)
        assertTrue(WardTier.FIREWALL in unmet)
        assertTrue(WardTier.TAILNET in unmet)
    }

    @Test
    fun `a mode is fully inert only when every tier it asks for is unavailable`() {
        assertTrue(
            WardMode.FIREWALL_ONLY.fullyInert(firewallAvailable = false, tailnetAvailable = true),
        )
        assertTrue(
            WardMode.TAILNET_ONLY.fullyInert(firewallAvailable = true, tailnetAvailable = false),
        )
        // DNS_FIREWALL still filters names without a privileged shell, so it is not inert.
        assertFalse(
            WardMode.DNS_FIREWALL.fullyInert(firewallAvailable = false, tailnetAvailable = false),
        )
        assertFalse(
            WardMode.DNS_ONLY.fullyInert(firewallAvailable = false, tailnetAvailable = false),
        )
    }
}
