package com.ant.emichaosbg

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
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

        /**
         * The native scan/detection engine, owned by the SERVICE rather than by the Activity.
         *
         * That ownership is the point. Scanning and alerting previously stopped the moment the
         * WebView went away, because the cadence lived in page JavaScript. Held here it keeps
         * running — and keeps committing findings to the encrypted log — with the app swiped
         * off recents and no WebView alive at all. MainActivity attaches a read-only view onto
         * this same instance instead of owning one of its own.
         */
        @Volatile
        var scanEngine: ScanEngine? = null
            private set

        /** Created lazily so the log's Keystore work happens off the Activity's critical path. */
        fun ensureScanEngine(ctx: Context): ScanEngine {
            scanEngine?.let { return it }
            synchronized(this) {
                scanEngine?.let { return it }
                val e = ScanEngine(ctx.applicationContext, SecureLog(ctx.applicationContext))
                scanEngine = e
                return e
            }
        }

        /**
         * Escalation detector, also service-owned. Same reasoning as the scan engine: a
         * detector that only runs while its UI is open misses precisely the window an attacker
         * would choose. Findings go to the encrypted log whether or not anything is watching.
         */
        @Volatile
        var escalationGuard: EscalationGuard? = null
            private set

        /** Cell monitoring is service-owned so a downgrade or area flip that happens while the
         *  app is backgrounded is still caught and logged. */
        @Volatile
        var cellSecurity: CellSecurity? = null
            private set

        fun ensureCellSecurity(ctx: Context): CellSecurity {
            cellSecurity?.let { return it }
            synchronized(this) {
                cellSecurity?.let { return it }
                val c = CellSecurity(ctx.applicationContext, SecureLog(ctx.applicationContext))
                cellSecurity = c
                return c
            }
        }

        /** LAN interception detector and the tower/position log — both service-owned, both
         *  driven from the background timer. Neither is ever called from the display loop:
         *  every one of them does binder or file I/O, and that is the class of call that
         *  froze the UI when the vault was being verified once a second. */
        @Volatile var netGuard: NetGuard? = null
            private set
        @Volatile var towerLog: TowerLog? = null
            private set

        fun ensureNetGuard(ctx: Context): NetGuard {
            netGuard?.let { return it }
            synchronized(this) {
                netGuard?.let { return it }
                val n = NetGuard(ctx.applicationContext, SecureLog(ctx.applicationContext))
                netGuard = n; return n
            }
        }

        fun ensureTowerLog(ctx: Context): TowerLog {
            towerLog?.let { return it }
            synchronized(this) {
                towerLog?.let { return it }
                val t = TowerLog(ctx.applicationContext)
                towerLog = t; return t
            }
        }

        /** BLE tracker/follower detection. Held by the service so the accumulated history
         *  outlives the WebView — the analysis and the evidence are native even though the scan
         *  cadence that feeds it is still page-driven. See TrackerWatch for the precise split. */
        @Volatile var trackerWatch: TrackerWatch? = null
            private set

        fun ensureTrackerWatch(ctx: Context): TrackerWatch {
            trackerWatch?.let { return it }
            synchronized(this) {
                trackerWatch?.let { return it }
                val vault = SecureLog(ctx.applicationContext)
                val t = TrackerWatch { sev, msg, badge -> vault.append(sev, msg, badge, "native") }
                trackerWatch = t; return t
            }
        }

        /** Service-owned BLE scanner feeding TrackerWatch. This is what completes the move:
         *  follower detection now observes with no WebView alive, which is the only state in
         *  which a planted tracker is actually followed for hours. */
        @Volatile var bleWatcher: BleWatcher? = null
            private set

        fun ensureBleWatcher(ctx: Context): BleWatcher {
            bleWatcher?.let { return it }
            synchronized(this) {
                bleWatcher?.let { return it }
                val b = BleWatcher(ctx.applicationContext, ensureTrackerWatch(ctx))
                bleWatcher = b; return b
            }
        }

        /** The Activity's TapjackGuard, published so native screens can read it without
         *  owning a second instance. Null until the Activity has built one. */
        @Volatile var tapjackRef: TapjackGuard? = null

        fun ensureEscalationGuard(ctx: Context): EscalationGuard {
            escalationGuard?.let { return it }
            synchronized(this) {
                escalationGuard?.let { return it }
                val g = EscalationGuard(ctx.applicationContext, SecureLog(ctx.applicationContext))
                escalationGuard = g
                return g
            }
        }
    }

    /** Slow cadence — these conditions are sticky, so polling hard would only cost battery. */
    private var escalationTimer: java.util.Timer? = null

    /** The position/tower log needs a shorter tick than the 5-minute security sweep, because
     *  its own interval and distance triggers decide whether a fix is actually recorded — this
     *  only has to offer it the chance often enough. Still a background thread. */
    private var towerTimer: java.util.Timer? = null

    private var wakeLock: android.os.PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        isRunning = false
        try { bleWatcher?.stop() } catch (_: Exception) {}
        try { escalationTimer?.cancel() } catch (_: Exception) {}
        escalationTimer = null
        try { towerTimer?.cancel() } catch (_: Exception) {}
        towerTimer = null
        destroyHeadless()
        try { wakeLock?.let { if (it.isHeld) it.release() } } catch (_: Exception) {}
        wakeLock = null
        super.onDestroy()
    }

    /**
     * Swiping the app off the recents screen destroys the Activity — and with it the WebView
     * that is actually generating the sound. `stopWithTask="false"` keeps THIS SERVICE alive,
     * but a surviving service with no WebView produces silence, which is worse than stopping:
     * a notification that claims to be masking while nothing comes out.
     *
     * So on task removal the service stands up its own headless WebView, loads the same page,
     * and tells it to start. It is never attached to a window — it exists only to keep the
     * Web Audio graph running inside a process the system is now willing to keep, because a
     * foreground service with a wake lock is holding it up.
     *
     * If that WebView cannot be created for any reason we stop the service outright rather
     * than leave a lying notification behind.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (!isRunning) return
        try {
            startHeadless()
        } catch (_: Throwable) {
            stopSelf()
        }
    }

    private var headless: android.webkit.WebView? = null

    private fun startHeadless() {
        if (headless != null) return
        val wv = android.webkit.WebView(this)
        wv.settings.javaScriptEnabled = true
        wv.settings.domStorageEnabled = true
        wv.settings.mediaPlaybackRequiresUserGesture = false
        wv.settings.allowFileAccess = true
        wv.addJavascriptInterface(EmiBridge(this, wv), "EMIBridge")
        wv.webViewClient = object : android.webkit.WebViewClient() {
            override fun onPageFinished(view: android.webkit.WebView?, url: String?) {
                // Auto-start the masker in the headless copy. Guarded so a page that has
                // already started doesn't double-start.
                view?.evaluateJavascript(
                    "(function(){try{var g=document.getElementById('go');" +
                    "if(g&&!document.body.classList.contains('live'))g.click();}catch(e){}})()",
                    null
                )
            }
        }
        wv.loadUrl("file:///android_asset/index.html")
        headless = wv
    }

    private fun destroyHeadless() {
        try { headless?.loadUrl("about:blank") } catch (_: Exception) {}
        try { headless?.destroy() } catch (_: Exception) {}
        headless = null
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

        // The service must advertise the MICROPHONE type as well, or mic capture is refused
        // while it runs — Android 11+ gates the mic on the FGS type, not only on RECORD_AUDIO,
        // and the refusal surfaces as a bare NotReadableError inside WebView. Declared
        // defensively: if the mic permission has not been granted, don't claim the type
        // (claiming a type you lack the permission for throws on Android 14+).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
            val micOk = androidx.core.content.ContextCompat.checkSelfPermission(
                this, android.Manifest.permission.RECORD_AUDIO
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
            if (micOk && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            }
            try { startForeground(1, n, types) }
            catch (_: Exception) { startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK) }
        } else {
            startForeground(1, n)
        }
        isRunning = true

        // Detection starts with the SERVICE, not with the page. This is what makes scanning
        // survive the WebView: findings continue to be detected and committed to the encrypted
        // log while the app is backgrounded or swiped away.
        try { ensureScanEngine(this).start() } catch (_: Throwable) {}
        // Follower detection now observes independently of the page. Failure here is reported
        // through status() rather than thrown: Bluetooth being off is an ordinary state, not
        // an error, and it must not take the masking service down with it.
        try { ensureBleWatcher(this).start() } catch (_: Throwable) {}

        // Escalation checks run on their own slow timer, independent of the WebView. A tracer
        // attaching or a library being injected while the app sits in the background is exactly
        // the case a UI-driven check would miss.
        if (escalationTimer == null) {
            escalationTimer = java.util.Timer("emi-escalation", true).also { t ->
                t.scheduleAtFixedRate(object : java.util.TimerTask() {
                    override fun run() {
                        try { ensureEscalationGuard(this@MaskerService).scan() } catch (_: Throwable) {}
                        // Cell checks run here too: a forced 4G->2G downgrade or a tracking-area
                        // flip is most useful to catch while the phone is sitting in a pocket,
                        // which is exactly when no UI is polling.
                        try { ensureCellSecurity(this@MaskerService).scan() } catch (_: Throwable) {}
                        try { ensureNetGuard(this@MaskerService).scan() } catch (_: Throwable) {}
                    }
                }, 8_000L, 5 * 60_000L)
            }
        }

        if (towerTimer == null) {
            towerTimer = java.util.Timer("emi-tower", true).also { t ->
                t.scheduleAtFixedRate(object : java.util.TimerTask() {
                    override fun run() {
                        try { ensureTowerLog(this@MaskerService).tick() } catch (_: Throwable) {}
                    }
                }, 10_000L, 15_000L)
            }
        }

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
