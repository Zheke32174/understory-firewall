package com.understory.godwall.ward

import com.understory.godwall.core.EngineState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HealthCheckTest {

    /** The all-clear baseline: an engaged, fully-capable, un-alarmed device. */
    private fun healthy() = HealthCheck.Input(
        enginePhase = EngineState.Phase.UP,
        engineDetail = "",
        mode = WardMode.DNS_FIREWALL,
        firewallTierAvailable = true,
        tailnetTierAvailable = true,
        otherVpnActive = false,
        paused = false,
        pauseRemainingMs = 0,
        lockdown = false,
        userCaCount = 0,
        selfBlockRules = 0,
        refusedDenials = 0,
        filterEnabled = true,
        blocklistDomains = 1200,
        leak = DnsLeak.Verdict.OK,
        childLockEngaged = false,
    )

    @Test
    fun `a healthy device raises nothing`() {
        assertTrue(HealthCheck.evaluate(healthy()).isEmpty())
        assertNull(HealthCheck.worst(emptyList()))
    }

    @Test
    fun `a failed engine is critical and carries the reason`() {
        val alerts = HealthCheck.evaluate(
            healthy().copy(
                enginePhase = EngineState.Phase.FAILED,
                engineDetail = "the slot was refused",
            ),
        )
        val first = alerts.first()
        assertEquals(HealthCheck.HealthAlert.ENGINE_FAILED, first.kind)
        assertEquals(HealthCheck.Severity.CRITICAL, first.severity)
        assertEquals("the slot was refused", first.args.first())
    }

    @Test
    fun `another VPN only matters while we are not holding the slot`() {
        val up = HealthCheck.evaluate(healthy().copy(otherVpnActive = true))
        assertFalse(up.any { it.kind == HealthCheck.HealthAlert.CONFLICTING_VPN })

        val down = HealthCheck.evaluate(
            healthy().copy(otherVpnActive = true, enginePhase = EngineState.Phase.DOWN),
        )
        assertTrue(down.any { it.kind == HealthCheck.HealthAlert.CONFLICTING_VPN })
    }

    @Test
    fun `a mode asking for a tier the device cannot run is warned about, not silently downgraded`() {
        val alerts = HealthCheck.evaluate(
            healthy().copy(mode = WardMode.FULL_STACK, firewallTierAvailable = false, tailnetTierAvailable = false),
        )
        assertTrue(alerts.any { it.kind == HealthCheck.HealthAlert.FIREWALL_TIER_INERT })
        assertTrue(alerts.any { it.kind == HealthCheck.HealthAlert.TAILNET_TIER_INERT })
    }

    @Test
    fun `a self-blocking rule is critical`() {
        val alerts = HealthCheck.evaluate(healthy().copy(selfBlockRules = 1))
        assertEquals(HealthCheck.Severity.CRITICAL, alerts.first { it.kind == HealthCheck.HealthAlert.SELF_BLOCK }.severity)
    }

    @Test
    fun `user CAs raise the MITM alert with the count`() {
        val alerts = HealthCheck.evaluate(healthy().copy(userCaCount = 2))
        val a = alerts.first { it.kind == HealthCheck.HealthAlert.MITM_USER_CA }
        assertEquals(2, a.args.first())
        assertEquals(HealthCheck.Severity.WARNING, a.severity)
    }

    @Test
    fun `an enabled filter with nothing loaded is a warning — the toggle is on, the block is not`() {
        val alerts = HealthCheck.evaluate(healthy().copy(blocklistDomains = 0))
        assertTrue(alerts.any { it.kind == HealthCheck.HealthAlert.FILTER_EMPTY })
        // …and switching the filter off is a choice, not a fault.
        val off = HealthCheck.evaluate(healthy().copy(blocklistDomains = 0, filterEnabled = false))
        assertFalse(off.any { it.kind == HealthCheck.HealthAlert.FILTER_EMPTY })
    }

    @Test
    fun `informational states are reported but never outrank a real fault`() {
        val alerts = HealthCheck.evaluate(
            healthy().copy(paused = true, lockdown = true, childLockEngaged = true, leak = DnsLeak.Verdict.LEAK),
        )
        assertEquals(HealthCheck.Severity.CRITICAL, HealthCheck.worst(alerts))
        assertEquals(HealthCheck.HealthAlert.DNS_LEAK, alerts.first().kind)
        assertTrue(alerts.any { it.kind == HealthCheck.HealthAlert.PAUSED })
        assertTrue(alerts.any { it.kind == HealthCheck.HealthAlert.LOCKDOWN_ON })
        assertTrue(alerts.any { it.kind == HealthCheck.HealthAlert.CHILD_LOCK_ON })
    }

    @Test
    fun `ordering is stable — severity first, then declaration order`() {
        val alerts = HealthCheck.evaluate(
            healthy().copy(userCaCount = 1, refusedDenials = 2, lockdown = true),
        )
        val kinds = alerts.map { it.kind }
        assertEquals(
            listOf(
                HealthCheck.HealthAlert.REFUSED_DENIALS,
                HealthCheck.HealthAlert.MITM_USER_CA,
                HealthCheck.HealthAlert.LOCKDOWN_ON,
            ),
            kinds,
        )
    }
}
