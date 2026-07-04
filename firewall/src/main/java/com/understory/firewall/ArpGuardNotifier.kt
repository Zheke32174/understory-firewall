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
 * The one place the ARP-guard watch talks to the notification system. Mirrors
 * [PostureWatchNotifier] exactly, with its own channel + notification id so the
 * two watchers never collide or share tuning.
 *
 * Honest by construction:
 *  - Copy NEVER claims we blocked or prevented anything — ARP spoofing cannot be
 *    prevented by a normal app. It says what the scan SAW and routes the user
 *    into the ArpGuard screen to review.
 *  - If POST_NOTIFICATIONS isn't granted we no-op; the in-app "last check" line
 *    still records the run so coverage is never overstated.
 */
object ArpGuardNotifier {

    const val CHANNEL_ID = "firewall_arp_guard"
    /** Distinct from FirewallVpnService.NOTIF_ID (1) and PostureWatch (2). */
    const val NOTIF_ID = 4

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
                    "ARP spoof alerts",
                    NotificationManager.IMPORTANCE_DEFAULT,
                )
                ch.description = "Notifies when a scheduled scan finds a changed gateway MAC, " +
                    "a MAC claiming several IPs, or a bogus gateway address. Detection only — " +
                    "this app cannot block ARP spoofing."
                ch.setShowBadge(true)
                nm.createNotificationChannel(ch)
            }
        }
    }

    /**
     * Post one summary notification for the [findings]. Title is the count; the
     * expanded body lists each finding, most-severe first. Silently no-ops when
     * [canNotify] is false.
     */
    fun notifyFindings(ctx: Context, findings: List<ArpGuard.Finding>) {
        if (findings.isEmpty()) return
        if (!canNotify(ctx)) {
            Diagnostics.log(
                "firewall.ArpGuardNotifier",
                "notifyFindings suppressed: notifications not permitted (${findings.size})",
            )
            return
        }
        ensureChannel(ctx)

        val title = if (findings.size == 1) "Net Audit: possible ARP spoofing"
        else "Net Audit: ${findings.size} ARP findings"
        val lines = findings.map { "• ${it.title}" }
        val collapsed = lines.first() + if (findings.size > 1) " (+${findings.size - 1} more)" else ""

        val openIntent = Intent(ctx, MainActivity::class.java).apply {
            action = Intent.ACTION_MAIN
            putExtra(MainActivity.EXTRA_OPEN_ROUTE, FirewallRoute.ArpGuard.name)
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
                "firewall.ArpGuardNotifier",
                "notify failed: ${it.javaClass.simpleName}: ${it.message}",
            )
        }
    }
}
</content>
