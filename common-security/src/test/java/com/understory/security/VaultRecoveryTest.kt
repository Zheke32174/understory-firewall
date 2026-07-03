package com.understory.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the app-agnostic parts of [VaultRecovery] that touch no
 * Android framework: the reset state machine ([VaultRecovery.ResetPlan]) and the
 * refresh-cadence predicate ([VaultRecovery.shouldPromptRefresh]).
 *
 * The Keystore-touching parts ([VaultRecovery.keyStateAtStartup],
 * [VaultRecovery.classifyUnlockFailure] over real KeyStore exceptions) are
 * exercised at the app layer where a real AndroidKeyStore exists;
 * [classifyUnlockFailure]'s branch logic is covered here with plain throwables
 * since that method only inspects types.
 */
class VaultRecoveryTest {

    // -------- ResetPlan: key usable path (export-first) --------

    @Test
    fun resetPlan_keyUsable_walksThroughExportFirst() {
        val p = VaultRecovery.ResetPlan(keyUsable = true)
        assertEquals(VaultRecovery.ResetStep.EXPLAIN, p.step)
        assertFalse(p.exportSatisfied)

        p.begin()
        assertEquals(VaultRecovery.ResetStep.EXPORT_FIRST, p.step)

        p.onExportDone()
        assertTrue(p.exportSatisfied)
        assertEquals(VaultRecovery.ResetStep.CONFIRM_WIPE, p.step)

        p.onWipeConfirmed()
        assertEquals(VaultRecovery.ResetStep.WIPING, p.step)

        p.onWiped()
        assertEquals(VaultRecovery.ResetStep.DONE, p.step)
    }

    @Test
    fun resetPlan_keyUsable_exportSkipStillReachesConfirm() {
        val p = VaultRecovery.ResetPlan(keyUsable = true)
        p.begin()
        p.onExportSkipped()
        assertEquals(VaultRecovery.ResetStep.CONFIRM_WIPE, p.step)
        // Skipping does NOT mark export satisfied — the user chose to lose data.
        assertFalse(p.exportSatisfied)
    }

    // -------- ResetPlan: key invalidated path (export impossible) --------

    @Test
    fun resetPlan_keyInvalidated_skipsExportStep() {
        val p = VaultRecovery.ResetPlan(keyUsable = false)
        // Export is inherently satisfied — there is nothing to export.
        assertTrue(p.exportSatisfied)
        p.begin()
        assertEquals(VaultRecovery.ResetStep.CONFIRM_WIPE, p.step)
    }

    // -------- ResetPlan: transitions are total; stray calls are no-ops --------

    @Test
    fun resetPlan_outOfOrderCallsAreNoOps() {
        val p = VaultRecovery.ResetPlan(keyUsable = true)
        // Calling wipe transitions before begin() must not desync the machine.
        p.onWipeConfirmed()
        assertEquals(VaultRecovery.ResetStep.EXPLAIN, p.step)
        p.onWiped()
        assertEquals(VaultRecovery.ResetStep.EXPLAIN, p.step)
        // A double begin() is idempotent.
        p.begin()
        p.begin()
        assertEquals(VaultRecovery.ResetStep.EXPORT_FIRST, p.step)
    }

    @Test
    fun resetPlan_confirmationMatchesWordOrAppName() {
        val p = VaultRecovery.ResetPlan(keyUsable = true)
        assertTrue(p.confirmationMatches("RESET", "Passgen"))
        assertTrue(p.confirmationMatches("reset", "Passgen"))
        assertTrue(p.confirmationMatches("  RESET  ", "Passgen"))
        assertTrue(p.confirmationMatches("passgen", "Passgen"))
        assertFalse(p.confirmationMatches("delete", "Passgen"))
        assertFalse(p.confirmationMatches("", "Passgen"))
    }

    // -------- shouldPromptRefresh --------

    @Test
    fun shouldPrompt_neverExported_promptsOnceThereIsSomethingToProtect() {
        val s = state(lastExportMs = 0L, lastExportItemCount = 0)
        assertFalse(VaultRecovery.shouldPromptRefresh(s, currentItemCount = 0, nowMs = 1_000L))
        assertTrue(VaultRecovery.shouldPromptRefresh(s, currentItemCount = 1, nowMs = 1_000L))
    }

    @Test
    fun shouldPrompt_itemDeltaThreshold() {
        val s = state(lastExportMs = 1_000L, lastExportItemCount = 10)
        // 4 new items: below the delta and not aged → no prompt.
        assertFalse(VaultRecovery.shouldPromptRefresh(s, currentItemCount = 14, nowMs = 2_000L))
        // 5 new items: hits the delta → prompt.
        assertTrue(VaultRecovery.shouldPromptRefresh(s, currentItemCount = 15, nowMs = 2_000L))
    }

    @Test
    fun shouldPrompt_ageThresholdNeedsAtLeastOneChange() {
        val old = 1_000L
        val aged = old + VaultRecovery.REFRESH_MAX_AGE_MS
        val s = state(lastExportMs = old, lastExportItemCount = 10)
        // Aged out but zero new items → no nag.
        assertFalse(VaultRecovery.shouldPromptRefresh(s, currentItemCount = 10, nowMs = aged))
        // Aged out with one new item → prompt.
        assertTrue(VaultRecovery.shouldPromptRefresh(s, currentItemCount = 11, nowMs = aged))
    }

    @Test
    fun onExported_advancesTimestampAndCount() {
        val s = state(lastExportMs = 0L, lastExportItemCount = 0)
        val after = VaultRecovery.onExported(s, nowMs = 42L, itemCount = 7)
        assertEquals(42L, after.lastExportMs)
        assertEquals(7, after.lastExportItemCount)
        // Verifier is carried unchanged (rotation goes through enroll()).
        assertEquals(s.verifier, after.verifier)
    }

    // -------- classifyUnlockFailure branch logic --------

    @Test
    fun classify_transientForGenericThrowable() {
        assertEquals(
            VaultRecovery.VaultKeyState.TRANSIENT_AUTH_FAILED,
            VaultRecovery.classifyUnlockFailure(RuntimeException("user cancelled")),
        )
    }

    private fun state(lastExportMs: Long, lastExportItemCount: Int) =
        VaultRecovery.RecoveryState(
            verifier = byteArrayOf(1, 2, 3),
            verifierSalt = byteArrayOf(4, 5, 6),
            lastExportMs = lastExportMs,
            lastExportItemCount = lastExportItemCount,
        )
}
