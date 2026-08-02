package com.understory.godwall.privilege

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle

/**
 * The receiving end of the Yojimbo privilege handshake.
 *
 * Yojimbo owns the privileged process, so Yojimbo owns the binder; the only way
 * for Godwall to obtain it is for Yojimbo to hand it over. That is what this
 * provider is for and it is all it does — every data method below is refused.
 *
 * Verification is done here, before [Privilege.attach] ever sees the binder:
 * the caller must be Yojimbo's package AND share our signing certificate. The
 * manifest additionally gates the provider behind the suite's signature-level
 * permission, so a non-suite caller cannot reach [call] at all.
 */
class YojimboPrivilegeProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val ctx = context ?: return refused("provider has no context")
        if (method != METHOD_ATTACH) return refused("unknown method '$method'")

        val caller = callingPackage
        if (!Privilege.callerIsYojimbo(ctx, caller)) {
            val why = "caller '${caller ?: "unknown"}' is not same-signature Yojimbo"
            Privilege.reject(why)
            return refused(why)
        }

        val binder = extras?.getBinder(EXTRA_SHELL)
            ?: return refused("no '$EXTRA_SHELL' binder in the call")

        Privilege.attach(binder)
        return Bundle().apply { putBoolean(RESULT_ACCEPTED, true) }
    }

    private fun refused(reason: String) = Bundle().apply {
        putBoolean(RESULT_ACCEPTED, false)
        putString(RESULT_REASON, reason)
    }

    // ---- Not a data provider. Everything else is refused, loudly. ----

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException("privilege provider is call()-only")

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("privilege provider is call()-only")

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = throw UnsupportedOperationException("privilege provider is call()-only")

    companion object {
        /** The one method: hand Godwall a privileged shell binder. */
        const val METHOD_ATTACH = "attachPrivilegedShell"

        /** Bundle key holding an [IPrivilegedShell] binder. */
        const val EXTRA_SHELL = "shell"

        const val RESULT_ACCEPTED = "accepted"
        const val RESULT_REASON = "reason"
    }
}
