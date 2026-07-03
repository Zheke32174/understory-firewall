package com.understory.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Receives the [PostureWatchScheduler] alarm (a periodic re-check) and the
 * BOOT_COMPLETED / package-replaced broadcasts (re-arm across reboots and app
 * updates, since AlarmManager alarms don't survive either).
 *
 * The re-check runs on Dispatchers.IO via a [goAsync] pending-result so the
 * PackageManager/AppOps scan doesn't block the main thread; we release the
 * result in a finally so the process isn't held alive longer than needed.
 * Everything is wrapped — a receiver that throws would be a hard crash, so this
 * one degrades to a Diagnostics line instead.
 */
class PostureWatchReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val appCtx = context.applicationContext
        when (intent.action) {
            PostureWatchScheduler.ACTION_CHECK -> handleCheck(appCtx)
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            -> handleReArm(appCtx, intent.action)
            else -> Diagnostics.log(
                "firewall.PostureWatchReceiver",
                "ignoring unexpected action: ${intent.action}",
            )
        }
    }

    /** A periodic re-check fired. Run the pass off-main, then re-arm. */
    private fun handleCheck(ctx: Context) {
        if (!PostureWatch.isEnabled(ctx)) {
            // Stale alarm after the user disabled the watch; do nothing (and
            // don't re-arm — disable() already cancelled).
            Diagnostics.log("firewall.PostureWatchReceiver", "check fired while disabled — dropping")
            return
        }
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                PostureWatch.runOnce(ctx)
            } catch (t: Throwable) {
                Diagnostics.error(
                    "firewall.PostureWatchReceiver",
                    "runOnce threw: ${t.javaClass.simpleName}: ${t.message}",
                )
            } finally {
                // Always re-arm the next one-shot, even if this run failed, so a
                // single bad pass doesn't silently end the schedule.
                runCatching { PostureWatchScheduler.schedule(ctx) }
                runCatching { pending.finish() }
            }
        }
    }

    /** Boot / update: alarms are gone, so re-arm iff the watch is enabled. */
    private fun handleReArm(ctx: Context, action: String?) {
        if (PostureWatch.isEnabled(ctx)) {
            runCatching { PostureWatchScheduler.schedule(ctx) }
            Diagnostics.log("firewall.PostureWatchReceiver", "re-armed after $action")
        }
    }
}
