package com.understory.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Receives the [ArpGuardWatchScheduler] alarm (a periodic ARP re-scan) and the
 * BOOT_COMPLETED / MY_PACKAGE_REPLACED broadcasts (re-arm across reboots and app
 * updates, since AlarmManager alarms don't survive either). Same shape as
 * [PostureWatchReceiver]: the scan runs on Dispatchers.IO via [goAsync] so it
 * doesn't block the main thread, and everything is wrapped so a receiver throw
 * can never become a hard crash.
 */
class ArpGuardWatchReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val appCtx = context.applicationContext
        when (intent.action) {
            ArpGuardWatchScheduler.ACTION_CHECK -> handleCheck(appCtx)
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            -> handleReArm(appCtx, intent.action)
            else -> Diagnostics.log(
                "firewall.ArpGuardWatchReceiver",
                "ignoring unexpected action: ${intent.action}",
            )
        }
    }

    private fun handleCheck(ctx: Context) {
        if (!ArpGuardWatch.isEnabled(ctx)) {
            Diagnostics.log("firewall.ArpGuardWatchReceiver", "check fired while disabled — dropping")
            return
        }
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                ArpGuardWatch.runOnce(ctx)
            } catch (t: Throwable) {
                Diagnostics.error(
                    "firewall.ArpGuardWatchReceiver",
                    "runOnce threw: ${t.javaClass.simpleName}: ${t.message}",
                )
            } finally {
                // Always re-arm the next one-shot so a single bad pass doesn't
                // silently end the schedule.
                runCatching { ArpGuardWatchScheduler.schedule(ctx) }
                runCatching { pending.finish() }
            }
        }
    }

    private fun handleReArm(ctx: Context, action: String?) {
        if (ArpGuardWatch.isEnabled(ctx)) {
            runCatching { ArpGuardWatchScheduler.schedule(ctx) }
            Diagnostics.log("firewall.ArpGuardWatchReceiver", "re-armed after $action")
        }
    }
}
