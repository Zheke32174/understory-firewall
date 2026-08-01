package com.ant.emichaosbg

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Foreground media-playback service. It holds no audio itself — the sound is generated
 * by the WebView's Web Audio graph — but promoting the process to a foreground
 * media-playback service keeps it alive and high-priority while the screen is off or
 * the app is backgrounded, matching the page's "background mode".
 */
class MaskerService : Service() {

    companion object {
        /** Read by EmiBridge.getResilienceStatus() so the UI can show whether the process is
         *  actually promoted, rather than assuming it because start was requested. */
        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var wakeLock: android.os.PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning = false
        try { wakeLock?.let { if (it.isHeld) it.release() } } catch (_: Exception) {}
        wakeLock = null
        super.onDestroy()
    }

    /** If the task is swiped away while masking is active, keep the service alive — the
     *  whole point of background mode is that closing the UI doesn't stop the masking. */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val channelId = "emi.masker"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(channelId) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(channelId, "Masker", NotificationManager.IMPORTANCE_LOW)
                )
            }
        }
        val n: Notification = Notification.Builder(this, channelId)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Masking active — audio only, does not radiate")
            .setSmallIcon(android.R.drawable.ic_lock_silent_mode_off)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK)
        } else {
            startForeground(1, n)
        }
        isRunning = true

        // A partial wake lock keeps the CPU available to the Web Audio graph with the screen
        // off. Without it, aggressive OEM dozing can stall the audio callback even inside a
        // foreground service — the masker goes quiet exactly when the room does.
        if (wakeLock == null) {
            try {
                val pm = getSystemService(android.os.PowerManager::class.java)
                wakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "emi:masker")
                    .also { it.setReferenceCounted(false); it.acquire() }
            } catch (_: Exception) {}
        }
        return START_STICKY
    }
}
