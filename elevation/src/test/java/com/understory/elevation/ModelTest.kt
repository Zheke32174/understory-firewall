package com.understory.elevation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the public model surface. No Android framework, no
 * elevation — these lock the wire values (private_dns strings), the ordinal
 * tie-break contract, and the Outcome/ShellResult shapes the UI branches on.
 */
class ModelTest {

    @Test
    fun tierOrdinalTieBreak_noneLowest_dhizukuHighest() {
        // grantedTier() relies on ordinal ordering as a stable "highest granted"
        // tie-break — pin it so a reordering of the enum can't silently flip
        // which tier a dual-granted app reports.
        assertTrue(ElevTier.NONE.ordinal < ElevTier.SHIZUKU.ordinal)
        assertTrue(ElevTier.SHIZUKU.ordinal < ElevTier.DHIZUKU.ordinal)
    }

    @Test
    fun privateDnsMode_settingValues_matchPlatformStrings() {
        assertEquals("off", PrivateDnsMode.OFF.settingValue)
        assertEquals("opportunistic", PrivateDnsMode.AUTOMATIC.settingValue)
        assertEquals("hostname", PrivateDnsMode.HOSTNAME.settingValue)
    }

    @Test
    fun shellResult_okOnlyWhenExitZero() {
        assertTrue(ShellResult(0, "ok", "").ok)
        assertFalse(ShellResult(1, "", "boom").ok)
        assertFalse(ShellResult(-1, "", "timeout").ok)
    }

    @Test
    fun outcome_isClosedSetTheUiCanBranchOn() {
        val outcomes: List<Outcome> = listOf(
            Outcome.Success("done"),
            Outcome.Unsupported("needs Shizuku"),
            Outcome.Failed("nope"),
        )
        // Exhaustive when — compiles only because Outcome is sealed.
        outcomes.forEach { o ->
            val label: String = when (o) {
                is Outcome.Success -> o.detail ?: "success"
                is Outcome.Unsupported -> o.reason
                is Outcome.Failed -> o.message
            }
            assertTrue(label.isNotEmpty())
        }
        assertNull((Outcome.Failed("x")).cause)
    }
}
