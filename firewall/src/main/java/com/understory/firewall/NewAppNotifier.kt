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
 * The one place the new-app install watch talks to the notification system.
 * Mirrors [ArpGuardNotifier] / [PostureWatchNotifier] (own channel + id).
 *
 * This is the donors' "get notified when a new app is installed" feature
 * (De1984, Fyrypt). Honest by construction: the notification says an app was
 * installed and routes into the per-app firewall to decide — it NEVER claims to
 * have blocked anything unless auto-block actually ran (that path posts a
 * different line, only after [BackendManager.setBlocked] succeeds).
 */
object NewAppNotifier {

    const val CHANNEL_ID = "firewall_new_app"
    /** Distinct from VpnService(1), PostureWatch(2), ArpGuard(4). Base id; per-app ids offset from it. */
    const val NOTIF_ID_BASE = 6000

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
                    "New app installed",
                    NotificationManager.IMPORTANCE_DEFAULT,
                )
                ch.description = "Notifies when a new app is installed so you can decide its " +
                    "network access. Detection + routing only, unless auto-block is on."
                ch.setShowBadge(true)
                nm.createNotificationChannel(ch)
            }
        }
    }

    /**
     * Post one notification for a freshly installed [pkg] with human [label].
     * [autoBlocked] flips the copy from "review" to "auto-blocked" — the caller
     * only passes true after the block actually applied.
     */
    fun notifyInstalled(ctx: Context, pkg: String, label: String, autoBlocked: Boolean) {
        if (!canNotify(ctx)) {
            Diagnostics.log("firewall.NewAppNotifier", "suppressed (notifications off): $pkg")
            return
        }
        ensureChannel(ctx)

        val title = if (autoBlocked) "New app auto-blocked: $label"
        else "New app installed: $label"
        val body = if (autoBlocked)
            "$pkg was blocked from the network on install. Tap to review or allow it."
        else "$pkg was installed. Tap to set its network access."

        val openIntent = Intent(ctx, MainActivity::class.java).apply {
            action = Intent.ACTION_MAIN
            putExtra(MainActivity.EXTRA_OPEN_ROUTE, FirewallRoute.AppFirewall.name)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        // Stable-per-package id so a re-install replaces the prior card rather than stacking.
        val notifId = NOTIF_ID_BASE + (pkg.hashCode() and 0xffff)
        val pending = PendingIntent.getActivity(
            ctx,
            notifId,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val notif = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()

        runCatching {
            (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager)
                ?.notify(notifId, notif)
        }.onFailure {
            Diagnostics.error("firewall.NewAppNotifier", "notify failed: ${it.message}")
        }
    }
}
