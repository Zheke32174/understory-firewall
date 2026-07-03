package com.understory.overlay.i2p

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import java.io.File

/**
 * Foreground service supervising the bundled i2pd binary.
 *
 * Phase α (now): the i2pd binary is **not** bundled. The service
 * starts, checks for the binary at `nativeLibraryDir/libi2pd.so`,
 * finds it missing, posts [I2pStatus.State.BinaryMissing], and stops
 * itself. No process is spawned. This is intentional — half-spawning
 * a userspace router with no reseed config is worse than not running
 * at all.
 *
 * Phase β (next): bundle i2pd via NDK cross-compile. See
 * `BUILD_RECIPE.md` for the integration steps. The `start*Binary`
 * paths below are the contract the supervised process must satisfy.
 *
 * Runs in the consumer app's process — this is a library module,
 * the service is merged into the consumer's manifest by AGP, and
 * the supervisor + observer (browser ProxyController toggle, future
 * firewall companion view) all live in one process. No IPC, no
 * Messenger, no AIDL.
 */
class I2pProxyService : Service() {

    private var process: Process? = null
    private var dataDir: File? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Promote to foreground first — Android kills services that take
        // too long to startForeground after onStartCommand. Same posture
        // as FirewallVpnService.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, buildNotification())
        }

        if (intent?.action == ACTION_STOP) {
            stopBinary()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        I2pStatus.update(I2pStatus.State.Starting)
        startBinary()
        return START_STICKY
    }

    override fun onDestroy() {
        stopBinary()
        super.onDestroy()
    }

    /**
     * Phase α: locate the bundled binary and bail honestly when it
     * isn't there. Phase β replaces this with the real ProcessBuilder
     * launch + readiness probe + state transitions.
     */
    private fun startBinary() {
        val binDir = File(applicationInfo.nativeLibraryDir)
        val candidate = File(binDir, "libi2pd.so")
        if (!candidate.exists()) {
            // Expected in phase α — no binary bundled. Surfaced as
            // BinaryMissing so the UI can show "I2P scaffolding only;
            // production builds add the binary."
            I2pStatus.update(I2pStatus.State.BinaryMissing)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        if (!candidate.canExecute()) {
            // Bundled but not runnable — packaging mistake (likely
            // missing useLegacyPackaging or an extractNativeLibs=false
            // miscombo). Honest error rather than silent retry-storm.
            I2pStatus.update(
                I2pStatus.State.Error("libi2pd.so present but not executable"),
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        // Phase β contract: ProcessBuilder + per-app dataDir +
        // configured i2pd.conf with httpproxy.address=127.0.0.1
        // httpproxy.port=4444, socksproxy.port=4447, then a
        // readiness probe (TCP connect to 4444 with retry) before
        // emitting Ready(httpPort=4444, socksPort=4447). Not
        // implemented in phase α — never partially-spawn the daemon.
        I2pStatus.update(
            I2pStatus.State.Error(
                "phase β: ProcessBuilder integration not yet implemented",
            ),
        )
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopBinary() {
        val p = process
        process = null
        runCatching { p?.destroyForcibly() }
        I2pStatus.update(I2pStatus.State.Idle)
    }

    private fun buildNotification(): android.app.Notification {
        ensureChannel()
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("understory · I2P proxy")
            .setContentText(
                when (val s = I2pStatus.state) {
                    I2pStatus.State.Idle -> "Idle"
                    I2pStatus.State.BinaryMissing -> "Scaffolding only — no binary bundled"
                    I2pStatus.State.Starting -> "Starting i2pd…"
                    is I2pStatus.State.Ready -> "Ready on 127.0.0.1:${s.httpPort}"
                    is I2pStatus.State.Error -> "Error: ${s.reason}"
                },
            )
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "I2P proxy",
                NotificationManager.IMPORTANCE_LOW,
            )
            ch.description = "Persistent notification while the I2P proxy supervisor is active."
            ch.setShowBadge(false)
            nm?.createNotificationChannel(ch)
        }
    }

    companion object {
        private const val CHANNEL_ID = "i2p_proxy"
        private const val NOTIF_ID = 4243
        const val ACTION_STOP = "com.understory.overlay.i2p.STOP"

        /** Start the supervisor. Idempotent — Android coalesces. */
        fun start(ctx: android.content.Context) {
            ctx.startForegroundService(
                Intent(ctx, I2pProxyService::class.java),
            )
        }

        /** Ask the supervisor to tear down. */
        fun stop(ctx: android.content.Context) {
            runCatching {
                ctx.startService(
                    Intent(ctx, I2pProxyService::class.java).apply {
                        action = ACTION_STOP
                    },
                )
            }
        }
    }
}
