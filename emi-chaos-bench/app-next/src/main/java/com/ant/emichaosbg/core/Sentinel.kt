package com.ant.emichaosbg.core

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import com.ant.emichaosbg.BleWatcher
import com.ant.emichaosbg.CellSecurity
import com.ant.emichaosbg.EscalationGuard
import com.ant.emichaosbg.Exporter
import com.ant.emichaosbg.NativeMic
import com.ant.emichaosbg.NetGuard
import com.ant.emichaosbg.OverlayGuard
import com.ant.emichaosbg.ScanEngine
import com.ant.emichaosbg.SecureLog
import com.ant.emichaosbg.TamperGuard
import com.ant.emichaosbg.TowerLog
import com.ant.emichaosbg.TrackerWatch
import com.ant.emichaosbg.UltrasonicWatch
import com.ant.emichaosbg.WifiScanBudget
import com.ant.emichaosbg.audio.NativeMasker
import org.json.JSONObject

/**
 * THE ONE OWNER OF EVERY DETECTOR IN THIS PROCESS.
 *
 * THE BUG THIS EXISTS TO KILL. In the previous build, `MaskerService.onStartCommand()`
 * was the only thing that started ScanEngine, BleWatcher, the escalation/cell/net
 * timer and the tower timer — and that service was startable from exactly two call
 * sites, `EmiBridge.kt:491` and `EmiBridge.kt:1010`, BOTH of them
 * `@JavascriptInterface` methods. So: launch the app, never press GO on the Masker
 * tab, and not one scanner ever ran. The Security screen then said "not yet run"
 * and the Data screen said "NOT SCANNING — service not started", forever. Applying
 * the project's own invariant mechanically — *if it has to ask the thing it
 * replaces, it has not replaced it* — the native shell had not replaced the page,
 * because it had to ask the page to start the scanners.
 *
 * So detection now starts from [com.ant.emichaosbg.MainActivity] on first frame,
 * and [SentinelService] exists to keep it running when the app is backgrounded —
 * not to be the thing that permits it to run at all.
 *
 * MASKING IS SUBORDINATE, NOT LOAD-BEARING. Audio masking is a self-contained
 * function that the user turns on and off. No detector's lifecycle is coupled to
 * it in either direction.
 *
 * EVERY DETECTOR IS CREATED ONCE. Seven separate SecureLog instances used to write
 * one file from six threads; there is one vault here and everything shares it.
 */
object Sentinel {

    @Volatile private var appCtx: Context? = null

    // ---- the vault: one instance, process-wide -------------------------------------
    lateinit var vault: SecureLog
        private set

    // ---- detectors -------------------------------------------------------------------
    lateinit var wifi: ScanEngine
        private set
    lateinit var tracker: TrackerWatch
        private set
    lateinit var ble: BleWatcher
        private set
    lateinit var net: NetGuard
        private set
    lateinit var cell: CellSecurity
        private set
    lateinit var escalation: EscalationGuard
        private set
    lateinit var integrity: TamperGuard
        private set
    lateinit var overlays: OverlayGuard
        private set
    lateinit var towers: TowerLog
        private set
    lateinit var exporter: Exporter
        private set

    // ---- audio: the second, entirely self-contained function -------------------------
    val masker = NativeMasker()
    lateinit var mic: NativeMic
        private set
    lateinit var ultrasonic: UltrasonicWatch
        private set

    /** Read by LogContext so every vault record says whether masking was live. */
    @Volatile var isMasking: Boolean = false
        private set

    @Volatile private var initialised = false
    @Volatile private var detecting = false
    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    @Volatile private var slowTicks = 0L
    @Volatile private var towerTicks = 0L
    @Volatile private var startedAt = 0L

    private const val SLOW_MS = 5 * 60_000L      // escalation / cellular / LAN
    private const val TOWER_MS = 15_000L         // tower+position sampling

    @Synchronized
    fun init(context: Context) {
        if (initialised) return
        val c = context.applicationContext
        appCtx = c
        vault = SecureLog(c)
        wifi = ScanEngine(c, vault)
        tracker = TrackerWatch { sev, msg, badge ->
            runCatching { vault.append(sev, msg, badge, "native") }
        }
        ble = BleWatcher(c, tracker)
        net = NetGuard(c, vault)
        cell = CellSecurity(c, vault)
        escalation = EscalationGuard(c, vault)
        integrity = TamperGuard(c)
        overlays = OverlayGuard(c)
        towers = TowerLog(c)
        exporter = Exporter(c)
        mic = NativeMic(c)
        ultrasonic = UltrasonicWatch(mic, vault)
        initialised = true
    }

    fun isInitialised() = initialised

    // ------------------------------------------------------------------ detection

    /**
     * Starts continuous detection. Idempotent, and safe to call from the Activity, the
     * service, or both — which is exactly what happens on a cold launch.
     */
    @Synchronized
    fun startDetection() {
        if (!initialised || detecting) return
        detecting = true
        startedAt = System.currentTimeMillis()
        runCatching { wifi.start() }
        runCatching { ble.start() }
        val t = HandlerThread("orb-sentinel").also { it.start() }
        thread = t
        handler = Handler(t.looper)
        // First slow sweep almost immediately, so a user who opens the app and goes
        // straight to Device sees a real result rather than "not yet run".
        handler?.postDelayed({ slowTick() }, 2_000L)
        handler?.postDelayed({ towerTick() }, TOWER_MS)
    }

    @Synchronized
    fun stopDetection() {
        detecting = false
        runCatching { wifi.stop() }
        runCatching { ble.stop() }
        handler?.removeCallbacksAndMessages(null)
        runCatching { thread?.quitSafely() }
        thread = null; handler = null
    }

    fun isDetecting() = detecting

    private fun slowTick() {
        if (!detecting) return
        // RETRY THE RADIOS. On a cold first launch the permission dialog is still on
        // screen when startDetection() runs, so BLE fails with "location permission not
        // granted" and Wi-Fi returns nothing. Without a retry the user grants the
        // permission and the scanners stay dead for the rest of the session — which is
        // indistinguishable, on screen, from a quiet room. Both are cheap no-ops when
        // they are already running.
        runCatching { if (!ble.isRunning()) ble.start() }
        runCatching { if (!wifi.isRunning()) wifi.start() }
        runCatching { escalation.scan() }
        runCatching { cell.scan() }
        runCatching { net.scan() }
        runCatching { integrity.status() }      // kicks a background integrity scan
        slowTicks++
        // The first few sweeps run fast so a permission granted seconds after launch is
        // picked up in seconds, not in five minutes.
        handler?.postDelayed({ slowTick() }, if (slowTicks < 3) 20_000L else SLOW_MS)
    }

    private fun towerTick() {
        if (!detecting) return
        runCatching { towers.tick() }
        towerTicks++
        handler?.postDelayed({ towerTick() }, TOWER_MS)
    }

    /**
     * Runs every on-demand detector once, in order, on the CALLING thread. This is what the
     * Sweep screen's one button does; the screen calls it off the main thread.
     */
    fun sweepBlocking(): String {
        val o = JSONObject()
        o.put("escalation", runCatching { JSONObject(escalation.scan()) }.getOrNull())
        o.put("cell", runCatching { JSONObject(cell.scan()) }.getOrNull())
        o.put("net", runCatching { JSONObject(net.scan()) }.getOrNull())
        o.put("integrity", runCatching { JSONObject(integrity.scanBlocking()) }.getOrNull())
        o.put("overlays", runCatching { JSONObject(overlays.status()) }.getOrNull())
        o.put("wifi", runCatching { JSONObject(wifi.snapshot()) }.getOrNull())
        o.put("ble", runCatching { JSONObject(ble.status()) }.getOrNull())
        o.put("tracker", runCatching { JSONObject(tracker.stats()) }.getOrNull())
        o.put("at", System.currentTimeMillis())
        return o.toString()
    }

    // ------------------------------------------------------------------ masking

    fun startMasking(): String {
        val r = masker.start()
        isMasking = masker.isRunning()
        return r
    }

    fun stopMasking() {
        masker.stop()
        isMasking = false
    }

    // ------------------------------------------------------------------ microphone

    fun startMic(): String {
        val r = mic.start()
        if (mic.isRunning()) ultrasonic.start()
        return r
    }

    fun stopMic() {
        ultrasonic.stop()
        mic.stop()
    }

    // ------------------------------------------------------------------ readout

    /** One honest line per subsystem for the Sweep screen's roll-up. */
    fun status(): String = JSONObject()
        .put("initialised", initialised)
        .put("detecting", detecting)
        .put("startedAt", startedAt)
        .put("slowSweeps", slowTicks)
        .put("towerSamples", towerTicks)
        .put("slowIntervalMs", SLOW_MS)
        .put("masking", isMasking)
        .put("micRunning", runCatching { mic.isRunning() }.getOrDefault(false))
        .put("wifiScanBudget", runCatching { JSONObject(WifiScanBudget.state()) }.getOrNull())
        .toString()
}
