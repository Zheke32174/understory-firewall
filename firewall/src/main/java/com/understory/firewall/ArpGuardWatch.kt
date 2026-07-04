package com.understory.firewall

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics

/**
 * The opt-in background re-scan for [ArpGuard], built on the SAME shape as
 * [PostureWatch] (an object holding state + a single `runOnce`, an inexact
 * [ArpGuardWatchScheduler] AlarmManager, a [ArpGuardWatchReceiver], and the
 * [ArpGuardNotifier]).
 *
 * BEST-EFFORT + HONEST (hard): a background pass can only read the neighbor table
 * when the Shizuku shell happens to be bound in the background. If it isn't, the
 * pass records "could not scan in the background" — it NEVER records a false
 * all-clear. State lives in the ArpGuard private SharedPreferences and never
 * leaves the device. This watch DETECTS only; it prevents nothing.
 */
object ArpGuardWatch {

    private const val PREF = "arp_guard_watch"
    private const val K_ENABLED = "enabled"
    private const val K_INTERVAL = "interval_hours"
    private const val K_LAST_RUN = "last_run_millis"
    private const val K_LAST_RESULT = "last_result"

    const val DEFAULT_INTERVAL_HOURS = 24
    const val MIN_INTERVAL_HOURS = 6
    const val MAX_INTERVAL_HOURS = 72

    /** The cadence choices offered in the UI (hours). */
    val INTERVAL_CHOICES = listOf(6, 12, 24, 72)

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun isEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(K_ENABLED, false)

    fun setEnabled(ctx: Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(K_ENABLED, enabled).apply()
    }

    fun getIntervalHours(ctx: Context): Int =
        prefs(ctx).getInt(K_INTERVAL, DEFAULT_INTERVAL_HOURS)

    fun setIntervalHours(ctx: Context, hours: Int) {
        prefs(ctx).edit()
            .putInt(K_INTERVAL, hours.coerceIn(MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS))
            .apply()
    }

    fun getLastRunMillis(ctx: Context): Long = prefs(ctx).getLong(K_LAST_RUN, 0L)

    fun getLastResult(ctx: Context): String? = prefs(ctx).getString(K_LAST_RESULT, null)

    private fun recordRun(ctx: Context, resultLine: String) {
        prefs(ctx).edit()
            .putLong(K_LAST_RUN, System.currentTimeMillis())
            .putString(K_LAST_RESULT, resultLine)
            .apply()
    }

    private fun clearHistory(ctx: Context) {
        prefs(ctx).edit().remove(K_LAST_RUN).remove(K_LAST_RESULT).apply()
    }

    /**
     * One background pass. Suspends (the caller runs it off-main). Never throws.
     *
     *  - If the Shizuku shell isn't bound in the background, records an HONEST
     *    "could not scan" line and returns — no notification, no false clear.
     *  - Otherwise scans, notifies only on findings that are NEW since the last
     *    alert (dedup via [ArpGuard.getNotifiedKeys]), and updates the dedup set
     *    so a standing finding alerts once. A finding that clears ages out and can
     *    re-alert on recurrence.
     */
    suspend fun runOnce(ctx: Context): String {
        if (!Elevation.canRunShell(ctx)) {
            val line = "Could not scan in the background — the Shizuku shell wasn't available. " +
                "Open the app to scan, or keep Shizuku running."
            recordRun(ctx, line)
            Diagnostics.log("firewall.ArpGuardWatch", "runOnce: shell unavailable in background")
            return line
        }

        val summary = when (val r = ArpGuard.scan(ctx)) {
            is ArpGuard.ScanResult.NeedsElevation -> {
                "Could not scan in the background — Shizuku access was not granted."
            }
            is ArpGuard.ScanResult.Failed -> {
                "Background scan couldn't read the neighbor table: ${r.message}"
            }
            is ArpGuard.ScanResult.Ok -> {
                val alreadyNotified = ArpGuard.getNotifiedKeys(ctx)
                val fresh = r.findings.filter { it.key !in alreadyNotified }
                if (fresh.isNotEmpty()) ArpGuardNotifier.notifyFindings(ctx, fresh)
                // Remember every CURRENT finding key so it isn't re-fired; cleared
                // findings drop out and could re-alert if they recur.
                ArpGuard.setNotifiedKeys(ctx, r.findings.map { it.key }.toHashSet())
                when {
                    fresh.isNotEmpty() -> "${fresh.size} new ARP finding(s) — you were notified."
                    r.findings.isNotEmpty() -> "No new findings (previously-flagged items still present)."
                    else -> "Checked ${r.neighbors.size} neighbor(s) — nothing suspicious."
                }
            }
        }
        recordRun(ctx, summary)
        Diagnostics.log("firewall.ArpGuardWatch", "runOnce: $summary")
        return summary
    }

    /** Turn the watch on: persist the flag and arm the alarm. */
    fun enable(ctx: Context) {
        setEnabled(ctx, true)
        ArpGuardWatchScheduler.schedule(ctx)
    }

    /** Turn the watch off: clear the flag, cancel the alarm, drop the history line. */
    fun disable(ctx: Context) {
        setEnabled(ctx, false)
        ArpGuardWatchScheduler.cancel(ctx)
        clearHistory(ctx)
    }
}
</content>
