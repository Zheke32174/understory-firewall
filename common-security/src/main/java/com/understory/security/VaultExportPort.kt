package com.understory.security

import java.io.InputStream
import java.io.OutputStream

/**
 * The port the shared export / import composables ([VaultExportScreen],
 * [VaultImportScreen]) call to do the actual envelope I/O.
 *
 * Why an interface here instead of calling `common-backup` directly: the module
 * dependency runs common-backup -> common-security, so a composable in
 * common-security cannot reference `com.understory.backup.VaultRecoveryEnvelope`
 * without inverting the graph. The app (which vendors BOTH modules) supplies a
 * tiny implementation that bridges to `VaultRecoveryEnvelope` +
 * `BackupAdapter`, keeping the shared UI app-agnostic exactly as the design
 * intends (§5.2) while respecting the existing module layout.
 *
 * A reference implementation an app writes (in the app module) is roughly:
 *
 * ```
 * object AppExportPort : VaultExportPort {
 *     override val appId = MyBackupAdapter.appId
 *     override val schemaVersion = MyBackupAdapter.schemaVersion
 *     override val appLabel = "Passgen"
 *     override fun buildPayload(unlocked: Any) = MyBackupAdapter.export()
 *     override fun writeEncrypted(out, payload, key, label) =
 *         VaultRecoveryEnvelope.writeEncrypted(out, appId, schemaVersion, payload, key, label)
 *     override fun peekAppId(input) = VaultRecoveryEnvelope.open(input).appId
 *     override fun decryptAndImport(input, key) {
 *         val opened = VaultRecoveryEnvelope.open(input)
 *         val payload = VaultRecoveryEnvelope.decrypt(opened, key)
 *         try { return MyBackupAdapter.import(payload, opened.schemaVersion) }
 *         finally { Crypto.wipe(payload) }
 *     }
 * }
 * ```
 *
 * All heavy work runs off the main thread inside the composables
 * (`Dispatchers.IO`, design §5.2 step 3), so implementations here may block.
 */
interface VaultExportPort {

    /** The adapter's app id, e.g. `com.understory.passgen`. */
    val appId: String

    /** The adapter's current export schema version. */
    val schemaVersion: Int

    /** Human app label used in copy, e.g. "Passgen". */
    val appLabel: String

    /**
     * Build the cleartext export payload from the already-unlocked vault. The
     * [unlocked] handle is whatever the app's unlock path produced; the shared
     * screen only passes back what the app gave it. Returns null when export is
     * impossible (key invalidated / vault not unlockable).
     */
    fun buildPayload(unlocked: Any?): ByteArray?

    /**
     * Write the encrypted envelope for [payload] under the recovery [key] to
     * [out]. Implementations delegate to
     * `VaultRecoveryEnvelope.writeEncrypted`, which wipes [payload]. Ownership
     * of [key] stays with the caller (the composable wipes it).
     */
    fun writeEncrypted(out: OutputStream, payload: ByteArray, key: CharArray, label: String)

    /**
     * Parse [input] far enough to read the envelope's target app id, WITHOUT
     * decrypting, so the import screen can reject a backup for another app
     * before prompting for the key (design §5.4 step 3).
     */
    fun peekAppId(input: InputStream): String

    /**
     * Decrypt [input] with recovery [key] and apply it via the app's
     * `BackupAdapter.import`, returning the human summary. Throws on a wrong
     * key / corrupt file (mapped to [RecoveryCopy.IMPORT_WRONG_KEY] by the UI).
     * Ownership of [key] stays with the caller.
     */
    fun decryptAndImport(input: InputStream, key: CharArray): String
}
