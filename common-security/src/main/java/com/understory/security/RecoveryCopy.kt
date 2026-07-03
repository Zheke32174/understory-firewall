package com.understory.security

/**
 * The single truthful vocabulary for every recovery / reset / export string in
 * the suite (design §6.2). One source so the "aegis says X, passgen says Y"
 * divergence cannot recur. These are plain strings (not string resources) so
 * adopting them adds no resource-merge coupling across the seven app repos; an
 * app that wants localization can map these to its own resources at the call
 * site.
 *
 * The copy is deliberately honest about the hardware-bound data-loss cliff:
 * where data is unrecoverable it says so, and it never promises a
 * fixed-seconds clipboard clear the code cannot keep (§6.3).
 */
object RecoveryCopy {

    // --- Invalidated-key detection / recovery landing (§2.2) ---

    /** Shown when [VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED]. */
    const val INVALIDATED_TITLE = "This vault's key was destroyed"

    const val INVALIDATED_BODY =
        "A fingerprint or face was added, or your screen lock changed, so " +
            "Android destroyed this vault's key. The encrypted data can no " +
            "longer be opened on this device. If you saved a recovery file, " +
            "restore it after resetting. Otherwise reset to start fresh."

    /** Transient auth failure — retry, do NOT offer reset. */
    const val TRANSIENT_RETRY =
        "Couldn't verify it was you. Try again."

    // --- Reset flow (§4.1) ---

    const val RESET_TITLE = "Reset vault"

    /** EXPLAIN copy when the key is still usable (deliberate reset). */
    const val RESET_EXPLAIN_KEY_USABLE =
        "Reset erases every item in this vault on this device. If you have a " +
            "recovery backup file you can restore it afterward. Export one now " +
            "if you haven't."

    /** EXPLAIN copy when the key was invalidated (export impossible). */
    const val RESET_EXPLAIN_KEY_INVALIDATED =
        "Android destroyed this vault's key when biometrics or your lock " +
            "changed. The items cannot be read on this device anymore. Reset " +
            "clears the unreadable data so you can start again. If you saved a " +
            "recovery backup earlier, you'll restore it after reset."

    const val RESET_EXPORT_FIRST = "Export a recovery backup first"

    const val RESET_EXPORT_SKIP = "Skip — I understand I'll lose these items"

    /** Destructive typed confirmation prompt. */
    fun resetConfirmPrompt(appName: String): String =
        "Type ${VaultRecovery.RESET_CONFIRM_WORD} (or \"$appName\") to erase this vault."

    const val RESET_CONFIRM_BUTTON = "Erase this vault"

    const val RESET_WIPING = "Erasing…"

    // --- Recovery-key enrollment / reveal (§3.3) ---

    const val RECOVERY_KEY_TITLE = "Save your recovery key"

    const val RECOVERY_KEY_BODY =
        "This key is the ONLY way to recover your vault if you re-enroll " +
            "biometrics, change your screen lock, or lose this phone. Save it " +
            "somewhere safe and off this device. We cannot recover it for you."

    /** Blocking typed / checkbox confirmation before Setup can finish. */
    const val RECOVERY_KEY_CONFIRM =
        "I saved this key — it is the only way to recover if I re-enroll " +
            "biometrics or lose this phone."

    // --- Out-of-date recovery banner (§3.5) ---

    fun refreshBanner(newItems: Int): String =
        "Your recovery backup is out of date ($newItems new item" +
            (if (newItems == 1) "" else "s") +
            "). Update it so you can restore everything."

    // --- Export / import (§5) ---

    const val EXPORT_TITLE = "Export recovery backup"

    const val EXPORT_ENCRYPTED_DEFAULT =
        "Writes an encrypted file only your recovery key can open. This is the " +
            "recommended backup."

    /** Second, distinct confirmation for the plaintext interop path (§5.3). */
    fun exportPlaintextWarning(incumbent: String): String =
        "This writes your secrets UNENCRYPTED so $incumbent can read them. " +
            "Anyone with the file can read them. Continue?"

    const val IMPORT_TITLE = "Restore from backup"

    /** header.appId mismatch (§5.4 step 3). */
    fun importWrongApp(otherAppLabel: String): String =
        "This backup is for Understory $otherAppLabel."

    const val IMPORT_WRONG_KEY =
        "Wrong recovery key or corrupted file."

    const val IMPORT_PROMPT_KEY = "Enter your recovery key"

    // --- Clipboard honesty (§6.3) ---

    /**
     * The ONLY honest toast for a best-effort, process-scoped clear. Never a
     * fixed-seconds promise the code can't keep across process death.
     */
    const val CLIPBOARD_COPIED_SESSION =
        "Copied. Cleared when you leave this screen."

    /**
     * For the recovery KEY specifically: prefer "Save to file" over clipboard.
     * If clipboard is offered anyway, this is the required warning.
     */
    const val CLIPBOARD_RECOVERY_KEY_WARNING =
        "Clipboard managers may keep a copy. Prefer Save to file."
}
