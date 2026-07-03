package com.understory.security

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import java.security.MessageDigest

/**
 * Base class every suite app extends to expose its
 * [SuiteCapabilityRegistry] capabilities.
 *
 * The subclass owns one number — [providedVersion] — which is the value
 * consumers look up in their KNOWN_PEERS table to translate into a
 * capability set. A peer never *tells* consumers what it can do; it only
 * confirms which version it is. This is the core defense against a
 * repackaged peer claiming bonus powers.
 *
 * Manifest declaration template (in each suite app):
 *
 *     <provider
 *         android:name=".SuiteCapsProvider"
 *         android:authorities="com.understory.passgen.suitecaps"
 *         android:exported="true"
 *         android:permission="com.understory.passgen.permission.READ_CAPS"
 *         android:grantUriPermissions="false" />
 *
 *     <permission
 *         android:name="com.understory.passgen.permission.READ_CAPS"
 *         android:protectionLevel="signature" />
 *
 *     <uses-permission android:name="com.understory.aegis.permission.READ_CAPS" />
 *     <uses-permission android:name="com.understory.firewall.permission.READ_CAPS" />
 *
 * Each app defines its OWN signature-protected permission for its OWN
 * provider, and declares uses-permission for every peer's permission.
 * `signature` protection means only same-cert callers can read — consumers
 * outside the suite cannot snoop the registry.
 *
 * The provider is read-only: insert/update/delete throw. The single
 * recognized URI is `content://{authority}/version`. Any other path
 * returns null.
 */
abstract class BaseCapabilityProvider : ContentProvider() {

    /**
     * The version number this peer attests. Consumers' KNOWN_PEERS
     * table translates this into a [SuiteCapability] set. Bump only when
     * adding new capabilities — bug-fix releases keep the number stable.
     */
    protected abstract val providedVersion: Int

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? {
        if (uri.lastPathSegment != "version") return null
        val ctx = context ?: return null
        val cursor = MatrixCursor(arrayOf(
            SuiteCapabilityRegistry.Cols.VERSION,
            SuiteCapabilityRegistry.Cols.CERT_SHA256,
        ))
        cursor.addRow(arrayOf<Any>(providedVersion, ownCertDigest(ctx)))
        return cursor
    }

    /** Provider is read-only by contract. */
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun getType(uri: Uri): String? =
        if (uri.lastPathSegment == "version")
            "vnd.android.cursor.item/vnd.com.understory.suitecaps.version"
        else null

    /**
     * Compute our own APK signing-cert sha256 for the diagnostic column.
     * Defensively returns "unavailable" on any failure — this is a
     * convenience field for cross-checking, not the primary trust anchor.
     */
    private fun ownCertDigest(ctx: android.content.Context): String = runCatching {
        val info = ctx.packageManager.getPackageInfo(
            ctx.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
        )
        val sig = info.signingInfo?.apkContentsSigners?.firstOrNull()
            ?: return@runCatching "unavailable"
        MessageDigest.getInstance("SHA-256")
            .digest(sig.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }.getOrDefault("unavailable")
}
