package com.understory.firewall

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.understory.security.Diagnostics

/**
 * Schedules the periodic posture re-check with the platform [AlarmManager] —
 * deliberately INEXACT, deliberately no WorkManager dependency. Inexact windowed
 * alarms are the battery-correct primitive for an opportunistic security
 * re-check; we never request the exact-alarm privilege, and the alarm is a
 * one-shot that each fire re-arms (so the cadence follows the user's current
 * interval choice without a reschedule-on-change dance).
 *
 * The alarm is delivered to [PostureWatchReceiver]. It does NOT wake the device
 * from Doze on a tight schedule; the OS is free to coalesce it into a
 * maintenance window, which is exactly what we want.
 */
object PostureWatchScheduler {

    /** The action that identifies a posture-watch alarm broadcast. */
    const val ACTION_CHECK = "com.understory.firewall.POSTURE_WATCH_CHECK"

    private const val REQUEST_CODE = 3001

    private fun alarmIntent(ctx: Context): PendingIntent {
        val intent = Intent(ctx, PostureWatchReceiver::class.java).apply {
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
     * Arm (or re-arm) the next re-check `intervalHours` from now. Idempotent:
     * FLAG_UPDATE_CURRENT means a second call just moves the single pending
     * alarm. Safe to call from the UI toggle, from each fired run, and from a
     * boot re-arm. Never throws.
     */
    fun schedule(ctx: Context) {
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: run {
            Diagnostics.error("firewall.PostureWatchScheduler", "AlarmManager unavailable")
            return
        }
        val intervalMs = PostureWatch.getIntervalHours(ctx).toLong() * 60L * 60L * 1000L
        val triggerAt = System.currentTimeMillis() + intervalMs
        runCatching {
            // setInexactRepeating would also work, but a self-re-arming one-shot
            // lets the interval change take effect on the very next fire without
            // us tracking a separate "reschedule" path. setAndAllowWhileIdle lets
            // the OS still deliver it during Doze maintenance windows — inexact,
            // battery-friendly, no exact-alarm privilege.
            am.setAndAllowWhileIdle(
                AlarmManager.RTC,
                triggerAt,
                alarmIntent(ctx),
            )
            Diagnostics.log(
                "firewall.PostureWatchScheduler",
                "scheduled next re-check in ${PostureWatch.getIntervalHours(ctx)}h",
            )
        }.onFailure {
            Diagnostics.error(
                "firewall.PostureWatchScheduler",
                "schedule failed: ${it.javaClass.simpleName}: ${it.message}",
            )
        }
    }

    /** Cancel any pending re-check (called when the user turns the watch off). */
    fun cancel(ctx: Context) {
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        runCatching { am.cancel(alarmIntent(ctx)) }
        Diagnostics.log("firewall.PostureWatchScheduler", "cancelled")
    }

    /**
     * Enable the watch: persist the flag, take an immediate baseline capture so
     * the first scheduled run has something to diff against (and so the user sees
     * a populated review screen right away), and arm the alarm. Runs the capture
     * inline — callers invoke this off the main thread.
     */
    fun enable(ctx: Context) {
        PostureWatch.setEnabled(ctx, true)
        // Establish a baseline now; diff() returns nothing on a null baseline, so
        // this also guarantees the first fire won't alert on pre-existing state.
        if (PostureWatch.getBaseline(ctx) == null) {
            runCatching { PostureWatch.saveBaseline(ctx, PostureWatch.capture(ctx)) }
        }
        schedule(ctx)
    }

    /** Disable the watch: clear the flag, cancel the alarm, wipe watcher state. */
    fun disable(ctx: Context) {
        PostureWatch.setEnabled(ctx, false)
        cancel(ctx)
        PostureWatch.clearState(ctx)
    }
}
