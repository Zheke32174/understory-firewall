package com.understory.firewall

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.understory.net.engine.DropStats
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The Standalone-mode engine (design-v2/firewall.md §3, §6-A1). Captures
 * outbound traffic from packages on the restrict set and DROPS it.
 *
 * WALLED-OFF: this service only ever runs in [FirewallMode.STANDALONE] with
 * the engine armed and the VpnSlotProbe guardrail PASSing. In Companion it
 * is never started — MainActivity never calls startEngine(). A registered-
 * but-dormant VpnService does not hold the slot (holding requires an
 * established session), so its manifest presence is doctrine-safe.
 *
 * One mode only: app-drop. The v1 DNS-redirect branch, /proc-net port
 * scanner, and DNSCrypt path are DROPPED (A9/A11/A8). The salvaged packet
 * code lives in :net-engine, compiled but not called here.
 *
 *   Establish a tun that captures only the restricted apps
 *   (addAllowedApplication per app). Read packets and drop them — the
 *   blocked apps find their connections silently fail. Apps not restricted
 *   bypass the tun and use the normal network unmodified.
 *
 *   When the restrict set is empty (or every entry is uninstalled) the
 *   service stays alive idle without establishing a tun, so the user can
 *   arm first and add apps incrementally.
 */
class FirewallVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var readerThread: Thread? = null
    /** Count of apps actually captured by the current tun. Drives the
     *  honest FGS notification (never claims "N blocked" when N of them
     *  are uninstalled). 0 while idle. */
    @Volatile private var establishedCount: Int = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Promote to foreground first — Android kills services that take
        // too long to startForeground. On Android 14+ the explicit type is
        // mandatory or the platform throws.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                buildNotification(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, buildNotification())
        }

        if (intent?.action == ACTION_STOP) {
            stopEngine()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        // Mark running BEFORE establish, so the new reader thread's
        // running.get() loop is true on first iteration.
        running.set(true)
        establish()
        return START_STICKY
    }

    override fun onDestroy() {
        stopEngine()
        super.onDestroy()
    }

    override fun onRevoke() {
        // A VPN just took the slot (Tailscale, another app, or the user
        // starting another tunnel). Neutral teardown (§8): NOT "preempted",
        // no banner, no "Re-enable" nag. The slot-watcher usually beats us
        // here, but onRevoke is the backstop.
        //
        //   engineArmed = false  → UI never claims we're filtering
        //   autoStopped = true   → the neutral hub line
        //   mode stays STANDALONE → the user hasn't left the mode; the
        //                           engine resumes when the slot frees
        FirewallSettings.setEngineArmed(this, false)
        FirewallSettings.setAutoStopped(this, true)
        stopEngine()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    private fun establish() {
        val restricted = FirewallSettings.getRestrictedPackages(this)

        if (restricted.isEmpty()) {
            idle()
            return
        }

        val builder = Builder()
            .setSession(getString(R.string.engine_session_name))
            // Reserved private-use IPv4 (RFC 5737) + IPv6 (RFC 3849). The
            // v6 address+route is essential: without it a restricted app on
            // a dual-stack network reaches the internet over IPv6 because
            // the tun only claimed the v4 default route — a real bypass.
            .addAddress(VPN_LOCAL_ADDR, 32)
            .addRoute("0.0.0.0", 0)
            .addAddress(VPN_LOCAL_ADDR_V6, 128)
            .addRoute("::", 0)
            .setMtu(MTU)
            .setBlocking(true)

        var added = 0
        for (pkg in restricted) {
            try {
                builder.addAllowedApplication(pkg)
                added++
            } catch (_: PackageManager.NameNotFoundException) {
                // Uninstalled since the rule was recorded. Skip.
            }
        }
        if (added == 0) {
            // Every restricted package is uninstalled. establish() with NO
            // addAllowedApplication would capture EVERY app — the silent
            // worst case. Treat like an empty set: idle.
            idle()
            return
        }

        val newTun = builder.establish()
        if (newTun == null) {
            // User may have revoked between prepare() and establish(). Bail.
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            running.set(false)
            return
        }

        // We hold the tun. Clear any sticky auto-stopped flag.
        FirewallSettings.setAutoStopped(this, false)
        establishedCount = added
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIF_ID, buildNotification())
        }

        // Atomic swap: publish the new fd + reader before tearing down the
        // old, so blocked apps never get a bypass window.
        val oldTun = tunFd
        val oldThread = readerThread
        tunFd = newTun

        readerThread = Thread({
            val input = FileInputStream(newTun.fileDescriptor)
            val buf = ByteArray(MTU)
            while (running.get()) {
                try {
                    val n = input.read(buf)
                    if (n < 0) break
                    DropStats.record()
                } catch (_: Throwable) {
                    break
                }
            }
        }, "firewall-tun-reader").also { it.start() }

        runCatching { oldTun?.close() }
        runCatching { oldThread?.join(500L) }
    }

    /** Tear down any prior tun and sit idle (foreground service alive, no
     *  tun). Lets the user arm before adding apps to restrict. */
    private fun idle() {
        runCatching { tunFd?.close() }
        tunFd = null
        runCatching { readerThread?.interrupt() }
        readerThread = null
        establishedCount = 0
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIF_ID, buildNotification())
        }
    }

    private fun stopEngine() {
        running.set(false)
        runCatching { tunFd?.close() }
        tunFd = null
        runCatching { readerThread?.interrupt() }
        readerThread = null
        establishedCount = 0
        // Counters track the current session — reset on full stop, but NOT
        // on the rule-change re-establish (which only swaps tuns).
        DropStats.reset()
    }

    private fun buildNotification(): android.app.Notification {
        ensureChannel()
        val pendingMain = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = Intent(this, FirewallVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        // Honest count: the number of apps ACTUALLY captured by the live
        // tun, not the size of the persisted restrict set (which may point
        // at uninstalled apps). An idle engine says "no apps blocked yet."
        val text = if (establishedCount > 0)
            "Blocking $establishedCount app(s)"
        else
            "Armed · no apps blocked yet"
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Standalone blocking active")
            .setContentText(text)
            .setOngoing(true)
            .setSilent(true)
            .setContentIntent(pendingMain)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", pendingStop)
            .build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
                val ch = NotificationChannel(
                    CHANNEL_ID,
                    "Standalone blocking status",
                    NotificationManager.IMPORTANCE_LOW,
                )
                ch.description = "Persistent notification while Standalone blocking is active."
                ch.setShowBadge(false)
                nm?.createNotificationChannel(ch)
            }
        }
    }

    companion object {
        const val CHANNEL_ID = "firewall_status"
        const val NOTIF_ID = 1
        const val ACTION_STOP = "com.understory.firewall.ACTION_STOP"
        // RFC 5737 192.0.2.0/24 — TEST-NET-1, never routes publicly.
        private const val VPN_LOCAL_ADDR = "192.0.2.42"
        // RFC 3849 2001:db8::/32 — the documentation prefix.
        private const val VPN_LOCAL_ADDR_V6 = "2001:db8::1"
        private const val MTU = 1500
    }
}
