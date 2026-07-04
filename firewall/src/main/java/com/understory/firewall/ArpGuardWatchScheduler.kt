package com.understory.firewall

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.understory.security.Diagnostics

/**
 * Schedules the periodic ARP re-scan with the platform [AlarmManager] — the same
 * inexact, no-WorkManager, self-re-arming one-shot shape as
 * [PostureWatchScheduler]. Inexact windowed alarms are the battery-correct
 * primitive for an opportunistic check; we never request the exact-alarm
 * privilege. The alarm is delivered to [ArpGuardWatchReceiver].
 *
 * Distinct action + request code from PostureWatch so the two schedules never
 * collide on the single pending-intent slot.
 */
object ArpGuardWatchScheduler {

    const val ACTION_CHECK = "com.understory.firewall.ARP_GUARD_CHECK"

    private const val REQUEST_CODE = 3101

    private fun alarmIntent(ctx: Context): PendingIntent {
        val intent = Intent(ctx, ArpGuardWatchReceiver::class.java).apply {
            action = ACTION_CHECK
        }
        return PendingIntent.getBroadcast(
            ctx,
            REQUEST_CODE,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    /**
     * Arm (or re-arm) the next re-scan `intervalHours` from now. Idempotent
     * (FLAG_UPDATE_CURRENT). Safe from the UI toggle, from each fired run, and
     * from a boot re-arm. Never throws.
     */
    fun schedule(ctx: Context) {
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: run {
            Diagnostics.error("firewall.ArpGuardWatchScheduler", "AlarmManager unavailable")
            return
        }
        val intervalMs = ArpGuardWatch.getIntervalHours(ctx).toLong() * 60L * 60L * 1000L
        val triggerAt = System.currentTimeMillis() + intervalMs
        runCatching {
            am.setAndAllowWhileIdle(AlarmManager.RTC, triggerAt, alarmIntent(ctx))
            Diagnostics.log(
                "firewall.ArpGuardWatchScheduler",
                "scheduled next ARP re-scan in ${ArpGuardWatch.getIntervalHours(ctx)}h",
            )
        }.onFailure {
            Diagnostics.error(
                "firewall.ArpGuardWatchScheduler",
                "schedule failed: ${it.javaClass.simpleName}: ${it.message}",
            )
        }
    }

    /** Cancel any pending re-scan (called when the user turns the watch off). */
    fun cancel(ctx: Context) {
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        runCatching { am.cancel(alarmIntent(ctx)) }
        Diagnostics.log("firewall.ArpGuardWatchScheduler", "cancelled")
    }
}
