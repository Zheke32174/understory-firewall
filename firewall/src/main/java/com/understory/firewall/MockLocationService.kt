package com.understory.firewall

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.understory.security.Diagnostics

/**
 * Foreground service that keeps the mock-location feed alive while active
 * (design doctrine: location-privacy, observe/advise — NEVER a VPN). It owns
 * the lifetime of the [MockLocationController] feed loop so the fake point keeps
 * being pushed while the screen is backgrounded, and shows a persistent
 * notification with a Stop action so the user is always aware it is running and
 * can end it in one tap.
 *
 * Started/stopped by [MockLocationScreen] via [start]/[stop]. The service is a
 * plain [Service] (not a VpnService) and holds no network slot.
 *
 * HONEST: the notification says exactly what is happening ("Feeding a mock GPS
 * location") and never implies any network protection. If the OS revokes the
 * mock-location slot mid-run the feed loop stops itself; this service stays up
 * only as long as it is meant to, and self-stops if started without params.
 */
class MockLocationService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Promote to foreground immediately (Android kills services that take
        // too long to call startForeground; on 14+ the type is mandatory).
        startInForeground()

        if (intent?.action == ACTION_STOP) {
            stopFeedAndSelf()
            return START_NOT_STICKY
        }

        // A null intent means Android re-delivered after a process kill. The
        // feed params are not persisted (privacy), so we can't honestly resume —
        // stop cleanly rather than pretend a feed is running.
        if (intent == null || intent.action != ACTION_START) {
            stopFeedAndSelf()
            return START_NOT_STICKY
        }

        val lat = intent.getDoubleExtra(EXTRA_LAT, Double.NaN)
        val lon = intent.getDoubleExtra(EXTRA_LON, Double.NaN)
        val accuracy = intent.getFloatExtra(EXTRA_ACCURACY, 5f)
        val jitter = intent.getFloatExtra(EXTRA_JITTER, 0f)

        when (val r = MockLocationController.start(this, lat, lon, accuracy, jitter)) {
            is MockLocationController.StartResult.Started -> {
                Diagnostics.log(TAG, "feed started via service")
                // Refresh the notification now that the feed is live.
                runCatching {
                    getSystemService(NotificationManager::class.java)
                        ?.notify(NOTIF_ID, buildNotification())
                }
            }
            else -> {
                // Could not start (not mock app / invalid / failed). Don't sit
                // as a zombie FGS — stop. The screen surfaces the reason via its
                // own direct call to the controller; the service never lies.
                Diagnostics.log(TAG, "feed start failed in service: $r")
                stopFeedAndSelf()
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        // Belt-and-braces: ensure the feed + test providers are torn down even
        // if we were killed without an explicit Stop.
        runCatching { MockLocationController.stop(this) }
        super.onDestroy()
    }

    private fun stopFeedAndSelf() {
        runCatching { MockLocationController.stop(this) }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startInForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                buildNotification(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, buildNotification())
        }
    }

    private fun buildNotification(): android.app.Notification {
        ensureChannel()
        val pendingMain = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                action = Intent.ACTION_MAIN
                putExtra(MainActivity.EXTRA_OPEN_ROUTE, FirewallRoute.MockLocation.name)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = Intent(this, MockLocationService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentTitle("Mock location active")
            .setContentText("Feeding a fake GPS location to apps. Tap to manage.")
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
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
                    "Mock location status",
                    NotificationManager.IMPORTANCE_LOW,
                )
                ch.description =
                    "Persistent notification shown while a mock GPS location is being fed to apps."
                ch.setShowBadge(false)
                nm?.createNotificationChannel(ch)
            }
        }
    }

    companion object {
        private const val TAG = "firewall.MockLocationService"
        const val CHANNEL_ID = "firewall_mock_location"
        /** Distinct from FirewallVpnService (1) and PostureWatch (2). */
        const val NOTIF_ID = 3
        const val ACTION_START = "com.understory.firewall.mock.ACTION_START"
        const val ACTION_STOP = "com.understory.firewall.mock.ACTION_STOP"
        private const val EXTRA_LAT = "com.understory.firewall.mock.LAT"
        private const val EXTRA_LON = "com.understory.firewall.mock.LON"
        private const val EXTRA_ACCURACY = "com.understory.firewall.mock.ACCURACY"
        private const val EXTRA_JITTER = "com.understory.firewall.mock.JITTER"

        /**
         * Start the feed as a foreground service. The screen should only call
         * this after the controller confirms the app holds the mock slot (or be
         * ready to surface [MockLocationController.StartResult.NotMockApp] from
         * its own pre-check), since the service self-stops on a failed start.
         */
        fun start(
            ctx: Context,
            lat: Double,
            lon: Double,
            accuracyM: Float,
            jitterM: Float,
        ) {
            val intent = Intent(ctx, MockLocationService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_LAT, lat)
                putExtra(EXTRA_LON, lon)
                putExtra(EXTRA_ACCURACY, accuracyM)
                putExtra(EXTRA_JITTER, jitterM)
            }
            runCatching { ctx.startForegroundService(intent) }
        }

        /** Stop the feed and the service. */
        fun stop(ctx: Context) {
            val intent = Intent(ctx, MockLocationService::class.java).apply {
                action = ACTION_STOP
            }
            // startService (not startForegroundService) is fine for a stop
            // command; if the service is already dead this is a harmless no-op.
            runCatching { ctx.startService(intent) }
        }
    }
}
