package com.understory.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Shared clipboard helper for the suite. Copies a CharArray (or pre-built
 * CharSequence) with the sensitive-content flag set so Android 13+
 * clipboard-history surfaces (Gboard, etc.) suppress preview, then
 * optionally schedules an auto-clear after [autoClearSeconds] using the
 * main-thread Handler.
 *
 * Both passgen and aegis share this so the auto-clear semantics match
 * across the suite — passgen sets it for the generated password,
 * aegis sets it for tap-to-copy TOTP codes.
 *
 * Using Handler instead of WorkManager keeps the manifest permission
 * list empty, which matters for a sideload-installable security tool.
 *
 * The [label] parameter discriminates which copies are "ours" — the
 * clear path checks both the label and the sensitive flag before
 * touching the clipboard, so a third-party app that overwrote the
 * clipboard between copy and clear isn't trampled.
 */
object Clipboard {

    const val SENSITIVE_FLAG: String = "android.content.extra.IS_SENSITIVE"

    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null
    private var pendingToken: Long = 0L
    private var pendingLabel: String = ""

    /**
     * Copy [chars] as a sensitive password / code. Schedules auto-clear
     * after [autoClearSeconds] if non-null and > 0; null disables clearing.
     * The caller still owns [chars] and is responsible for wiping it.
     */
    fun copySensitive(
        context: Context,
        chars: CharArray,
        autoClearSeconds: Int?,
        label: String = "password",
    ) {
        copyInternal(context, String(chars), autoClearSeconds, label)
    }

    /**
     * Variant that takes a CharSequence directly, used when the caller
     * has already materialized the secret (e.g. a TOTP code computed in
     * a tight scope and never held in CharArray form).
     */
    fun copySensitive(
        context: Context,
        text: CharSequence,
        autoClearSeconds: Int?,
        label: String = "password",
    ) {
        copyInternal(context, text, autoClearSeconds, label)
    }

    private fun copyInternal(
        context: Context,
        text: CharSequence,
        autoClearSeconds: Int?,
        label: String,
    ) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        // Pass `text` directly to ClipData.newPlainText so we don't
        // hold a redundant local reference extending the secret's life.
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = PersistableBundle().apply {
            putBoolean(SENSITIVE_FLAG, true)
        }
        cm.setPrimaryClip(clip)

        pendingClear?.let { handler.removeCallbacks(it) }
        pendingClear = null

        if (autoClearSeconds != null && autoClearSeconds > 0) {
            val token = System.nanoTime()
            pendingToken = token
            pendingLabel = label
            val app = context.applicationContext
            val r = Runnable { clearIfOurs(app, token) }
            pendingClear = r
            handler.postDelayed(r, autoClearSeconds * 1000L)
        }
    }

    /**
     * Clears the clipboard only if the current primary clip looks like
     * one we set (sensitive flag present and our [pendingLabel]) and
     * the token still matches.
     */
    fun clearIfOurs(context: Context, expectedToken: Long): Boolean {
        if (pendingToken != expectedToken) return false
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val desc: ClipDescription? = cm.primaryClipDescription
        val ours = desc?.label == pendingLabel &&
            desc.extras?.getBoolean(SENSITIVE_FLAG, false) == true
        if (ours) {
            cm.clearPrimaryClip()
        }
        pendingToken = 0L
        pendingClear = null
        pendingLabel = ""
        return ours
    }
}
