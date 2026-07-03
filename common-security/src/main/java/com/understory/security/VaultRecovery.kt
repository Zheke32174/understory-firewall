package com.understory.security

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException

/**
 * Shared vault recovery / reset contract for the four vault-bearing apps
 * (passgen, aegis, vault-folder, backups). Design: docs/design-v2/
 * shared-vault-recovery.md.
 *
 * The four apps each carry a clone of the same v2 vault engine: a random
 * 32-byte KEK wrapped by an auth-bound Keystore key built with
 * [Crypto.setInvalidatedByBiometricEnrollment]`(true)` (Crypto.kt:165). That
 * flag is a deliberate anti-coercion property — enrolling a new fingerprint or
 * changing the lock screen makes the Keystore destroy the wrap key, and the
 * on-disk KEK becomes permanently un-unwrappable. No software can undo that.
 *
 * This object provides the two honest answers to that fact:
 *
 *   1. [classifyUnlockFailure] / [keyStateAtStartup] — DETECT the invalidation
 *      precisely so the unlock path stops dead-ending the user with a generic
 *      "decryption failed" and can route to a clean reset instead.
 *   2. [RecoveryKey] + [RecoveryEnrollment] + [ResetPlan] — the user-held,
 *      NOT-Keystore-bound recovery material minted proactively at create time,
 *      so "reset" does not mean "lose everything". The recovery material is a
 *      `common-backup` [com.understory.backup.BackupEnvelope] encrypted under
 *      the recovery key (see [VaultRecoveryEnvelope] in common-backup), never
 *      the hardware-wrapped KEK.
 *
 * This is a pure contract: no Activity / Composable imports live here so the
 * apps can call it from their unlock Activity, their Setup flow, or a headless
 * migration. The shared UI is [VaultRecoveryScreen] / [VaultExportScreen] /
 * [VaultImportScreen]; the app-supplied glue is [VaultResetHooks].
 */
object VaultRecovery {

    /**
     * The state of a vault's device-auth Keystore key, distinguished so the
     * unlock path can stop conflating three very different situations behind
     * one "Vault decryption failed" string.
     */
    enum class VaultKeyState {
        /** Key present and usable — proceed to BiometricPrompt. */
        OK,

        /** No alias and/or no header — first run or post-reset. Route to Setup. */
        NEVER_CREATED,

        /**
         * Re-enrollment or lock-screen change destroyed the key. The on-disk
         * KEK can no longer be unwrapped on this device. Route to the Recovery
         * screen ([VaultRecoveryScreen]); the only paths forward are reset (to
         * regain a usable app) and, if the user saved one, restore from a
         * recovery export.
         */
        PERMANENTLY_INVALIDATED,

        /**
         * User cancelled, hit a lockout, or presented a wrong biometric — the
         * key is fine, the auth attempt was not. Retryable; do NOT offer reset
         * for this (that is the inverse of the current over-broad dead-end).
         */
        TRANSIENT_AUTH_FAILED,
    }

    /**
     * Classify a throwable caught from the unlock path
     * ([Crypto.deviceAuthCipherForDecrypt] init, BiometricPrompt callback, or
     * `cipher.doFinal`). [KeyPermanentlyInvalidatedException] is a subclass of
     * [java.security.InvalidKeyException]; it can surface either directly or
     * wrapped, so both the throwable and its cause are checked.
     */
    fun classifyUnlockFailure(t: Throwable): VaultKeyState =
        when {
            t is KeyPermanentlyInvalidatedException ||
                t.cause is KeyPermanentlyInvalidatedException ->
                VaultKeyState.PERMANENTLY_INVALIDATED
            t is UserNotAuthenticatedException ||
                t.cause is UserNotAuthenticatedException ->
                VaultKeyState.TRANSIENT_AUTH_FAILED
            // BiometricPrompt error codes surfaced by the caller (cancel,
            // lockout, no-match) all reduce to "try again".
            else -> VaultKeyState.TRANSIENT_AUTH_FAILED
        }

    /**
     * The reliable pre-prompt classification. [headerExists] is the app's own
     * "vault file present" check (e.g. `Vault.exists(ctx)`). When the key was
     * invalidated, the alias is dropped from the Keystore, so
     * [Crypto.deviceAuthKeyExists] returns false while the header is still on
     * disk — that mismatch is the signal to skip a doomed BiometricPrompt and
     * go straight to the Recovery screen. The
     * [KeyPermanentlyInvalidatedException] catch in [classifyUnlockFailure] is
     * the belt-and-braces path for devices that keep the alias but fail at
     * `doFinal`.
     */
    fun keyStateAtStartup(ctx: Context, headerExists: Boolean): VaultKeyState =
        when {
            !headerExists -> VaultKeyState.NEVER_CREATED
            // header on disk but the wrap key is gone = invalidated & swept.
            !Crypto.deviceAuthKeyExists() -> VaultKeyState.PERMANENTLY_INVALIDATED
            else -> VaultKeyState.OK
        }

    // ---------------------------------------------------------------------
    // Recovery key — NOT bound to the biometric Keystore key (design §3)
    // ---------------------------------------------------------------------

    /** Recovery key size — 32 bytes, ~190 bits after Argon2id. */
    const val RECOVERY_KEY_BYTES: Int = 32

    /**
     * A freshly minted recovery secret, independent of the vault KEK. This is
     * the ONLY thing that survives re-enrollment and device loss. It is the
     * Argon2id passphrase over a [com.understory.backup.BackupEnvelope]
     * ([VaultRecoveryEnvelope] in common-backup) whose payload is the app's
     * cleartext export — so restoring reconstructs CONTENTS onto a fresh vault
     * (new device, new KEK), rather than transplanting a raw hardware KEK.
     *
     * Ownership: this class owns [chars]. Call [wipe] when finished (e.g. in a
     * Compose `DisposableEffect`/`finally`), mirroring backups' reveal screen
     * which wipes at dispose (MainActivity.kt:960-965).
     */
    class RecoveryKey internal constructor(val chars: CharArray) {

        /** Best-effort zero-out of the underlying buffer. */
        fun wipe() = Crypto.wipe(chars)

        /**
         * A stable, non-secret verifier the app persists locally so a later
         * "make a recovery backup" or an import prompt can prove the user
         * entered the same key. Argon2id(key, [verifierSalt]); the salt is
         * stored alongside. Storing the verifier (not the key) locally is safe:
         * it is one-way and useless to an attacker without the key.
         */
        fun verifier(verifierSalt: ByteArray): ByteArray =
            Crypto.argon2id(chars, verifierSalt)
    }

    /** Mint a new [RecoveryKey] from the CSPRNG. */
    fun newRecoveryKey(): RecoveryKey {
        val raw = Crypto.randomBytes(RECOVERY_KEY_BYTES)
        try {
            return RecoveryKey(RecoveryKeyCodec.encode(raw))
        } finally {
            Crypto.wipe(raw)
        }
    }

    /**
     * Reconstruct a [RecoveryKey] from user-entered [chars] (e.g. pasted or
     * transcribed on a new device). Accepts either the grouped
     * word-hyphen transcription form or the raw base64-no-pad form
     * (see [RecoveryKeyCodec]). The returned key takes ownership of a
     * normalized copy; the caller still owns and must wipe [chars].
     */
    fun recoveryKeyFrom(chars: CharArray): RecoveryKey =
        RecoveryKey(RecoveryKeyCodec.normalize(chars))

    /**
     * Verify user-entered [entered] against a stored [verifier]/[verifierSalt]
     * pair (constant-time). Used by the create-time typed confirmation and by
     * import to catch a wrong key before a doomed Argon2id+GCM decrypt.
     */
    fun verifyRecoveryKey(
        entered: RecoveryKey,
        verifier: ByteArray,
        verifierSalt: ByteArray,
    ): Boolean {
        val got = entered.verifier(verifierSalt)
        try {
            return constantTimeEquals(got, verifier)
        } finally {
            Crypto.wipe(got)
        }
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    // ---------------------------------------------------------------------
    // Create-time enrollment — MANDATORY (design §3.3)
    // ---------------------------------------------------------------------

    /**
     * The persistent, non-secret recovery bookkeeping an app stores so the
     * shared prompt cadence ([shouldPromptRefresh]) and the create-time
     * verifier work. Apps that hold no SharedPreferences (vault-folder) keep a
     * tiny dedicated `recovery_state.bin`; apps that do can serialize this into
     * their existing prefs. All fields are non-secret.
     */
    data class RecoveryState(
        /** Argon2id verifier of the current recovery key (non-secret). */
        val verifier: ByteArray,
        /** Salt for [verifier]. */
        val verifierSalt: ByteArray,
        /** Wallclock millis of the last successful recovery EXPORT (0 = none). */
        val lastExportMs: Long,
        /** Item count captured at the last recovery export. */
        val lastExportItemCount: Int,
    ) {
        // data class with ByteArray members: identity equals is fine here (we
        // never key a set/map on RecoveryState), and overriding would be dead
        // code. Kept explicit so a future author doesn't add a broken default.
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = System.identityHashCode(this)
    }

    /**
     * Build the initial [RecoveryState] for a freshly minted [RecoveryKey].
     * Called by the app's Setup flow right after create succeeds, to persist
     * the verifier (so the typed confirmation and future imports can check the
     * key) BEFORE landing in the vault list. The full initial export can be
     * deferred; the key MUST be shown now (design §3.3 step 2).
     */
    fun enroll(key: RecoveryKey, itemCount: Int = 0): RecoveryState {
        val salt = Crypto.randomBytes(Crypto.SALT_BYTES)
        val verifier = key.verifier(salt)
        return RecoveryState(
            verifier = verifier,
            verifierSalt = salt,
            lastExportMs = 0L,
            lastExportItemCount = itemCount,
        )
    }

    /**
     * Return an updated [RecoveryState] after a successful recovery export at
     * [nowMs] capturing [itemCount]. Rotating the recovery key
     * (re-export under a new key) replaces the verifier via [enroll] instead.
     */
    fun onExported(prev: RecoveryState, nowMs: Long, itemCount: Int): RecoveryState =
        prev.copy(lastExportMs = nowMs, lastExportItemCount = itemCount)

    // ---------------------------------------------------------------------
    // "Make a recovery backup" prompt cadence (design §3.5)
    // ---------------------------------------------------------------------

    /** Suggested new-item threshold that triggers the refresh banner. */
    const val REFRESH_ITEM_DELTA: Int = 5

    /** Suggested elapsed-time threshold (30 days) that triggers the banner. */
    const val REFRESH_MAX_AGE_MS: Long = 30L * 24 * 60 * 60 * 1000

    /**
     * Pure predicate for the non-blocking "your recovery backup is out of date"
     * banner on the vault list. No scheduling, no background work — the app
     * calls this on the vault-list composition with its live [currentItemCount]
     * and [nowMs]. Returns true when the vault has gained
     * >= [REFRESH_ITEM_DELTA] items since the last export, OR when
     * >= [REFRESH_MAX_AGE_MS] has elapsed since the last export with any change.
     * Never true when no export has ever happened AND there is nothing to back
     * up yet (create-time enrollment covers the initial case).
     */
    fun shouldPromptRefresh(
        state: RecoveryState,
        currentItemCount: Int,
        nowMs: Long,
    ): Boolean {
        val newItems = currentItemCount - state.lastExportItemCount
        if (state.lastExportMs == 0L) {
            // Never exported: prompt as soon as there is anything to protect.
            return currentItemCount > state.lastExportItemCount
        }
        if (newItems >= REFRESH_ITEM_DELTA) return true
        val aged = (nowMs - state.lastExportMs) >= REFRESH_MAX_AGE_MS
        return aged && newItems > 0
    }

    // ---------------------------------------------------------------------
    // Reset state machine (design §4)
    // ---------------------------------------------------------------------

    /**
     * The uniform reset flow, export-first then wipe+reinit, expressed as a
     * small state machine so the four ad-hoc dead-ends collapse into one.
     * [VaultRecoveryScreen] drives an instance of this; it carries no UI and no
     * app-specific logic, so it is unit-testable and identical across apps.
     *
     * ```
     * [Explain] --(key usable)--> [ExportFirst] --> [ConfirmWipe] --> [Wiping] --> [Done]
     *           \--(key invalidated: export impossible)---------> [ConfirmWipe] --> [Wiping] --> [Done]
     * ```
     */
    enum class ResetStep {
        /** Honest explanation of what is lost; copy varies by [keyUsable]. */
        EXPLAIN,

        /**
         * Offered ONLY when the key is still usable — launches the export
         * ([VaultExportScreen]) so the user does not reset over un-backed-up
         * data. Skippable via an explicit "Skip — I'll lose these items".
         */
        EXPORT_FIRST,

        /** Typed destructive confirmation (type `RESET` or the app name). */
        CONFIRM_WIPE,

        /** [VaultResetHooks.wipe] is running. */
        WIPING,

        /** Wipe complete; route to Setup. */
        DONE,
    }

    /**
     * Drives [ResetStep]. Constructed with whether the key is still usable
     * (deliberate reset with an openable vault) or invalidated (re-enrollment,
     * export impossible). All transitions are explicit and total; unexpected
     * calls are no-ops rather than throwing, so a double-tap can't desync the
     * screen.
     */
    class ResetPlan(val keyUsable: Boolean) {

        var step: ResetStep = ResetStep.EXPLAIN
            private set

        /** True once the user has completed (or skipped) the export step. */
        var exportSatisfied: Boolean = !keyUsable
            private set

        /** Advance from EXPLAIN. Routes past export when the key is unusable. */
        fun begin() {
            if (step != ResetStep.EXPLAIN) return
            step = if (keyUsable) ResetStep.EXPORT_FIRST else ResetStep.CONFIRM_WIPE
        }

        /** User finished a real export. */
        fun onExportDone() {
            if (step != ResetStep.EXPORT_FIRST) return
            exportSatisfied = true
            step = ResetStep.CONFIRM_WIPE
        }

        /** User explicitly skipped the export ("I understand I'll lose these"). */
        fun onExportSkipped() {
            if (step != ResetStep.EXPORT_FIRST) return
            step = ResetStep.CONFIRM_WIPE
        }

        /** Typed confirmation accepted; begin the wipe. */
        fun onWipeConfirmed() {
            if (step != ResetStep.CONFIRM_WIPE) return
            step = ResetStep.WIPING
        }

        /** [VaultResetHooks.wipe] returned. */
        fun onWiped() {
            if (step != ResetStep.WIPING) return
            step = ResetStep.DONE
        }

        /**
         * Whether [confirmation] matches the required destructive token. The
         * app name or the literal word `RESET` (case-insensitive, trimmed) both
         * pass. Kept here so the check is identical across apps.
         */
        fun confirmationMatches(confirmation: String, appName: String): Boolean {
            val c = confirmation.trim()
            return c.equals(RESET_CONFIRM_WORD, ignoreCase = true) ||
                c.equals(appName.trim(), ignoreCase = true)
        }
    }

    /** The literal word the user types to confirm a reset. */
    const val RESET_CONFIRM_WORD: String = "RESET"
}

/**
 * App-supplied glue for the shared reset flow. One thin implementation per app;
 * all app-specific vault knowledge lives behind these four calls so
 * [VaultRecoveryScreen] stays app-agnostic (design §4.2).
 *
 * Reference wiring per app:
 *  - passgen:      `Vault.delete(ctx)` + [Crypto.deleteDeviceAuthKey].
 *  - aegis:        `AegisVault.delete(ctx)` (already deletes file + key).
 *  - vault-folder: delete every folder dir under the vault-folder root; the
 *                  single device-auth key backs them all, so one
 *                  [Crypto.deleteDeviceAuthKey] invalidates all folders — reset
 *                  wipes the whole root, which is correct (re-enrollment already
 *                  bricked all folders together).
 *  - backups:      delete `header.bin` + local snapshots dir + key. Envelopes
 *                  already written to SAF stay decryptable with the recovery
 *                  key and are NOT touched by reset.
 */
interface VaultResetHooks {

    /** Does this app's vault currently exist on disk? */
    fun exists(ctx: Context): Boolean

    /**
     * Produce the cleartext export payload for the export-first step, given the
     * app's already-unlocked vault handle. Returns null when the key is
     * invalidated and the vault cannot be unlocked (export impossible). The
     * concrete type of [unlocked] is the app's own unlocked-vault object; the
     * shared screen only ever passes back what the app handed it.
     */
    fun exportPayload(unlocked: Any): ByteArray?

    /** Delete all vault files AND the device-auth Keystore key. */
    fun wipe(ctx: Context)

    /** Route to the app's Setup flow (fresh KEK, key, mandatory enrollment). */
    fun goToSetup()
}
