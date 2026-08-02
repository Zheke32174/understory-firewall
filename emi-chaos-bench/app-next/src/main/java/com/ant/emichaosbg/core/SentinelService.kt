package com.ant.emichaosbg.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.ant.emichaosbg.MainActivity
import com.ant.emichaosbg.R

/**
 * The foreground service that keeps detection alive with the app backgrounded.
 *
 * WHAT IT IS NOT. It is NOT the gate on whether detection runs. [Sentinel] is
 * started from the Activity's first frame, and this service is started right
 * after it; if the service is killed, refused, or never granted a notification,
 * the detectors still ran and the screens still show real results. That inversion
 * is the whole point — the previous build's equivalent service was the ONLY
 * starter of every scanner, and it could only be started from page JavaScript.
 *
 * FOREGROUND-SERVICE TYPE IS EARNED, NOT CLAIMED. It starts as `dataSync` only.
 * `mediaPlayback` is added to the running type mask when the user turns masking
 * on, and `microphone` when they turn the mic monitor on — never before, and both
 * are dropped again when they turn them off. Android 11+ gates microphone access
 * behind the foreground-service TYPE and not just the RECORD_AUDIO permission, so
 * this is also what makes the mic monitor work at all with the screen off.
 */
class SentinelService : Service() {

    companion object {
        private const val CHANNEL = "orb.sentinel"
        private const val NOTIF_ID = 4201

        const val ACTION_START = "com.ant.emichaosbg.SENTINEL_START"
        const val ACTION_SYNC_TYPE = "com.ant.emichaosbg.SENTINEL_SYNC"
        const val ACTION_STOP = "com.ant.emichaosbg.SENTINEL_STOP"

        @Volatile var running = false
            private set

        /** Start (or refresh) the sentinel. Safe to call repeatedly. */
        fun start(ctx: Context) = send(ctx, ACTION_START)

        /**
         * Re-evaluate the foreground-service type after masking or the mic was
         * toggled. Called by the UI right after [Sentinel.startMasking] etc.
         */
        fun syncType(ctx: Context) = send(ctx, ACTION_SYNC_TYPE)

        fun stop(ctx: Context) = send(ctx, ACTION_STOP)

        private fun send(ctx: Context, action: String) {
            val i = Intent(ctx, SentinelService::class.java).setAction(action)
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i)
                else ctx.startService(i)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        Sentinel.init(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            running = false
            Sentinel.stopDetection()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        goForeground()
        running = true
        // Idempotent — the Activity already called this on its first frame.
        Sentinel.startDetection()
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        super.onDestroy()
    }

    private fun goForeground() {
        var type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC else 0
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (Sentinel.isMasking) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
            if (runCatching { Sentinel.mic.isRunning() }.getOrDefault(false))
                type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
        }
        runCatching { ServiceCompat.startForeground(this, NOTIF_ID, notification(), type) }
    }

    private fun notification(): Notification {
        val tap = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val what = buildString {
            append("Detectors running")
            if (Sentinel.isMasking) append(" · masking")
            if (runCatching { Sentinel.mic.isRunning() }.getOrDefault(false)) append(" · mic")
        }
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(what)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(tap)
            .build()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL) != null) return
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL, getString(R.string.sentinel_channel), NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.sentinel_channel_desc)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
        )
    }
}
