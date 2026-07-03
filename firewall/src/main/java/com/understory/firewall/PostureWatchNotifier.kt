package com.understory.firewall

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.understory.security.Diagnostics

/**
 * The one place the posture-watch feature talks to the notification system.
 * Honest by construction:
 *  - The channel is IMPORTANCE_DEFAULT (a security change is worth a heads-up)
 *    but distinct from the Standalone FGS channel so the user can tune them
 *    separately.
 *  - Copy NEVER claims we blocked anything — it says what CHANGED and routes the
 *    user into the app to review. Tapping opens the Posture Watch screen.
 *  - If POST_NOTIFICATIONS is not granted we no-op (the run still updates the
 *    in-app "last check" line, so the user isn't lied to about coverage).
 */
object PostureWatchNotifier {

    const val CHANNEL_ID = "firewall_posture_watch"
    /** Distinct from FirewallVpnService.NOTIF_ID (1) so the two never collide. */
    const val NOTIF_ID = 2

    /** True iff the app may actually post a notification right now. */
    fun canNotify(ctx: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                ctx, Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return false
        }
        return runCatching {
            (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager)
                ?.areNotificationsEnabled() ?: false
        }.getOrDefault(false)
    }

    private fun ensureChannel(ctx: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                val ch = NotificationChannel(
                    CHANNEL_ID,
                    "Posture change alerts",
                    NotificationManager.IMPORTANCE_DEFAULT,
                )
                ch.description = "Notifies when a scheduled re-check finds a new " +
                    "remote-admin grant, Private DNS turned off, or a dropped VPN. " +
                    "Observation only — this app blocks nothing."
                ch.setShowBadge(true)
                nm.createNotificationChannel(ch)
            }
        }
    }

    /**
     * Post one summary notification for the [changes] found this run. The title
     * is the count; the expanded body lists each change, most-severe first.
     * Silently no-ops when [canNotify] is false.
     */
    fun notifyChanges(ctx: Context, changes: List<PostureWatch.Change>) {
        if (changes.isEmpty()) return
        if (!canNotify(ctx)) {
            Diagnostics.log(
                "firewall.PostureWatchNotifier",
                "notifyChanges suppressed: notifications not permitted (${changes.size} change(s))",
            )
            return
        }
        ensureChannel(ctx)

        val title = if (changes.size == 1) "Net Audit: 1 posture change"
        else "Net Audit: ${changes.size} posture changes"
        val lines = changes.map { "• ${it.summary}" }
        val collapsed = lines.first() + if (changes.size > 1) " (+${changes.size - 1} more)" else ""

        // Tap → open the app on the Posture Watch review screen.
        val openIntent = Intent(ctx, MainActivity::class.java).apply {
            action = Intent.ACTION_MAIN
            putExtra(MainActivity.EXTRA_OPEN_ROUTE, FirewallRoute.PostureWatch.name)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pending = PendingIntent.getActivity(
            ctx,
            NOTIF_ID,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val style = NotificationCompat.InboxStyle()
            .setBigContentTitle(title)
            .setSummaryText("Review in Net Audit — nothing was blocked")
        lines.forEach { style.addLine(it) }

        val notif = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(collapsed)
            .setStyle(style)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()

        runCatching {
            (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager)
                ?.notify(NOTIF_ID, notif)
        }.onFailure {
            Diagnostics.error(
                "firewall.PostureWatchNotifier",
                "notify failed: ${it.javaClass.simpleName}: ${it.message}",
            )
        }
    }
}
