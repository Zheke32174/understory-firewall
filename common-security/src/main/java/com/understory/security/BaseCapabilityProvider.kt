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
 *         android:readPermission="com.understory.suite.CAPS"
 *         android:writePermission="com.understory.suite.CAPS_WRITE"
 *         android:grantUriPermissions="false" />
 *
 *     <permission
 *         android:name="com.understory.suite.CAPS"
 *         android:protectionLevel="signature" />
 *     <permission
 *         android:name="com.understory.suite.CAPS_WRITE"
 *         android:protectionLevel="signature" />
 *
 *     <uses-permission android:name="com.understory.suite.CAPS" />
 *
 * ONE shared signature-protected permission ([SUITE_CAPS_PERMISSION]),
 * declared identically in every suite app (first installed definition
 * wins per Android semantics; identical same-cert declarations make
 * that safe). `signature` protection means only same-cert callers can
 * read — consumers outside the suite cannot snoop the registry.
 * [SUITE_CAPS_WRITE_PERMISSION] is defined but never requested by any
 * app, so the write side of the provider is permanently locked.
 *
 * The provider is read-only: insert/update/delete throw. The single
 * recognized URI is `content://{authority}/version`. Any other path
 * returns null.
 */
abstract class BaseCapabilityProvider : ContentProvider() {

    companion object {
        /** Shared signature-level read permission — see class KDoc. */
        const val SUITE_CAPS_PERMISSION = "com.understory.suite.CAPS"

        /** Declared in every manifest, requested by none: a locked write gate. */
        const val SUITE_CAPS_WRITE_PERMISSION = "com.understory.suite.CAPS_WRITE"
    }

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
        // Belt-and-braces re-check of the manifest readPermission: if a
        // vendored manifest ever drops the attribute, remote callers
        // without the suite permission still get nothing. Same-process
        // callers pass because the app holds its own uses-permission.
        if (ctx.checkCallingOrSelfPermission(SUITE_CAPS_PERMISSION)
            != PackageManager.PERMISSION_GRANTED
        ) return null
        val cursor = MatrixCursor(arrayOf(
            SuiteCapabilityRegistry.Cols.VERSION,
            SuiteCapabilityRegistry.Cols.CERT_SHA256,
        ))
        cursor.addRow(arrayOf<Any>(providedVersion, ownCertDigest(ctx)))
        return cursor
    }

    /** Provider is read-only by structure — writes always throw. */
    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException("read-only provider")
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = throw UnsupportedOperationException("read-only provider")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("read-only provider")
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
