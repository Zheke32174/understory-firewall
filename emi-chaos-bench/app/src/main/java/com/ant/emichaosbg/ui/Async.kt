package com.ant.emichaosbg.ui

import android.os.Handler
import android.os.Looper
import android.view.View
import java.util.concurrent.Executors

/**
 * THE RULE THESE SCREENS BROKE, MADE STRUCTURAL.
 *
 * The first native screens froze the app on open, and the cause was not subtle once looked at:
 * every one of them gathered its data on the MAIN THREAD. SecureLog's constructor makes
 * directories and its first use generates a Keystore key (StrongBox key generation is not
 * fast); EscalationGuard reads /proc/self/maps line by line; NetGuard reads /proc/net/arp;
 * CellSecurity makes binder calls into the telephony stack. Any one of those is enough to drop
 * frames, and on a cold Keystore it is enough to hang.
 *
 * That is the SAME failure the page version had — the vault verifying itself once a second on
 * the UI thread — reproduced in Kotlin. Moving work native does not make it cheap; it only
 * changes which language the blocking call is written in. Writing that here rather than in one
 * screen's comment because the mistake was systemic, not local.
 *
 * So: no screen calls a detector directly. They call [load], which runs the gather on a shared
 * background thread and posts the result back. The UI thread only ever assigns strings to
 * TextViews.
 */
object Async {

    private val exec = Executors.newSingleThreadExecutor { r ->
        Thread(r, "emi-ui-data").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())

    /**
     * Gather off the main thread, apply on it. [apply] is skipped if the view has been detached
     * in the meantime, so a screen the user navigated away from cannot touch dead views.
     */
    fun <T> load(view: View, gather: () -> T, apply: (T) -> Unit) {
        exec.execute {
            val result = runCatching(gather).getOrNull() ?: return@execute
            main.post {
                if (view.isAttachedToWindow) runCatching { apply(result) }
            }
        }
    }

    /** Fire-and-forget background work with no UI result (exports, toggles). */
    fun run(work: () -> Unit) = exec.execute { runCatching(work) }
}
