package com.ant.emichaosbg

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

/**
 * SERVICE-OWNED BLE SCANNING — the remaining half of moving follower detection out of the
 * WebView.
 *
 * TrackerWatch already held the heuristics and the record natively, but its input still came
 * from the page's scan cadence, so nothing was observed once the WebView went away. For every
 * other detector that is a robustness nicety. For this one it is the whole feature: a tracker
 * planted in a bag is followed for hours with the phone in a pocket and the screen off, which
 * is exactly the window the page-driven version could not see.
 *
 * ONE SCANNER FOR THE WHOLE APP, and that is not a detail. When this class was added it ran
 * alongside the page's own scan registration — two concurrent scans in one process, exactly
 * the mistake that had already been made with the Wi-Fi budget. It costs three ways:
 *
 *   - Android limits SCAN STARTS (about five per thirty seconds per app) and answers the rest
 *     with SCAN_FAILED_APPLICATION_REGISTRATION_FAILED, which looks identical to an empty room
 *     if it is not reported.
 *   - Two registrations with different modes do not average. The radio runs at the most
 *     aggressive one requested, so the page's LOW_LATENCY scan silently overrode the LOW_POWER
 *     setting here — meaning the comment that used to sit in this spot, claiming the emission
 *     was held at the platform minimum, was simply false whenever the page was scanning.
 *   - Battery, continuously, for duplicate data.
 *
 * So this is now the only component in the app that registers a scan. Results fan out from
 * here to both consumers: TrackerWatch for analysis, and the page for display via the callback
 * it already had. The page asks this to deliver rather than starting its own.
 *
 * SCAN MODE. LOW_POWER, legacy advertisements only. Android exposes no passive/active toggle —
 * a normal LE scan does emit SCAN_REQ, the one transmit this app performs and documented as
 * such elsewhere. With the second registration gone, LOW_POWER now genuinely is what the radio
 * runs at, which matters because this runs continuously in the background rather than in
 * bursts a user initiated.
 *
 * THE PLATFORM'S OWN LIMITER IS RESPECTED RATHER THAN FOUGHT. Android allows roughly five scan
 * starts per thirty seconds per app and silently ignores the rest — an over-eager scanner does
 * not see more, it just gets dropped while still costing power. So this starts ONE scan and
 * leaves it running, harvesting into a buffer, rather than restarting on a cadence. The chaotic
 * cadence in the page exists to make the app's own timing unpredictable; that is an audio and
 * main-thread concern and has nothing to do with catching a tracker, which wants steady
 * observation over hours.
 *
 * SNAPSHOTS ARE SCAN SESSIONS. Results accumulate between flushes and are handed to
 * TrackerWatch as one batch, which is what makes its persistence counter meaningful: a device
 * seen two hundred times in one window is one session, not two hundred.
 */
class BleWatcher(
    private val ctx: Context,
    private val watch: TrackerWatch
) {

    @Volatile private var running = false
    private var thread: HandlerThread? = null
    private var handler: Handler? = null
    private var scanner: BluetoothLeScanner? = null

    /** address -> most recent view of that device within the current window. */
    private val buffer = HashMap<String, JSONObject>()
    private var flushes = 0L
    private var seenTotal = 0L
    private var lastError: String? = null

    private val FLUSH_MS = 20_000L

    /**
     * Everything currently buffered, WITHOUT touching the radio — no extra scan start and no
     * mode escalation. The BLE screen reads this to show what is in range right now, alongside
     * TrackerWatch's accumulated per-identity view.
     */
    @Synchronized
    fun buffered(): List<JSONObject> = buffer.values.toList()

    private val cb = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            harvest(result)
        }
        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            results.forEach { harvest(it) }
        }
        override fun onScanFailed(errorCode: Int) {
            // Named rather than swallowed. SCAN_FAILED_APPLICATION_REGISTRATION_FAILED in
            // particular means the platform's start limiter has been hit, which looks exactly
            // like "there are no devices around" if it is not reported.
            lastError = when (errorCode) {
                SCAN_FAILED_ALREADY_STARTED -> "already started"
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED ->
                    "registration failed — usually the platform scan-start limiter"
                SCAN_FAILED_INTERNAL_ERROR -> "internal error"
                SCAN_FAILED_FEATURE_UNSUPPORTED -> "feature unsupported on this device"
                else -> "scan failed ($errorCode)"
            }
        }
    }

    @Synchronized
    private fun harvest(r: ScanResult) {
        val addr = try { r.device?.address ?: return } catch (_: SecurityException) { return }
        val o = JSONObject()
        o.put("address", addr)
        o.put("rssi", r.rssi)
        val rec = r.scanRecord
        if (rec != null) {
            // Manufacturer data is the payload that survives MAC rotation — the thing
            // TrackerWatch keys identities on.
            val mfg = JSONObject()
            val md = rec.manufacturerSpecificData
            for (i in 0 until md.size()) {
                val id = md.keyAt(i)
                val bytes = md.valueAt(i) ?: continue
                mfg.put(id.toString(), bytes.joinToString("") { b -> "%02x".format(b) })
            }
            if (mfg.length() > 0) o.put("mfg", mfg)
            val svcs = JSONArray()
            rec.serviceUuids?.forEach { svcs.put(it.uuid.toString()) }
            if (svcs.length() > 0) o.put("services", svcs)
            rec.deviceName?.let { o.put("name", it) }
        }
        buffer[addr] = o
        seenTotal++
    }

    /**
     * Every failure path RECORDS its reason before returning it.
     *
     * It previously only returned the reason as a String, and the sole caller —
     * MaskerService's `try { ensureBleWatcher(this).start() } catch {}` — discarded it. The
     * result was that status() reported running=false with no error field, so the Data screen
     * printed "idle": Bluetooth switched off, location permission never granted, and a genuinely
     * quiet room all rendered identically.
     *
     * For a follower detector that is the worst possible failure. "No tracker is following you"
     * and "this never looked" must never be the same words on screen — the whole value of the
     * SCANNER cell is telling those two apart. So lastError is set on the way out of every
     * branch, and cleared only on a scan that actually registered.
     */
    fun start(): String {
        if (running) return "already running"

        fun fail(reason: String): String { lastError = reason; return reason }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_SCAN)
            != PackageManager.PERMISSION_GRANTED) return fail("BLUETOOTH_SCAN not granted")
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) return fail("location permission not granted")

        val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: return fail("no BluetoothManager")
        val ad = bm.adapter ?: return fail("no Bluetooth adapter")
        if (!ad.isEnabled) return fail("Bluetooth is off")
        val s = ad.bluetoothLeScanner ?: return fail("no LE scanner (Bluetooth off?)")

        val t = HandlerThread("emi-ble").also { it.start() }
        thread = t; handler = Handler(t.looper)
        scanner = s
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
            .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) setLegacy(true) }
            .build()
        return try {
            s.startScan(null, settings, cb)
            running = true
            lastError = null
            schedule()
            "ok"
        } catch (e: SecurityException) { "denied: ${e.message}" }
          catch (e: Throwable) { "failed: ${e.javaClass.simpleName}" }
    }

    fun stop() {
        running = false
        try { scanner?.stopScan(cb) } catch (_: Throwable) {}
        handler?.removeCallbacksAndMessages(null)
        try { thread?.quitSafely() } catch (_: Throwable) {}
        thread = null; handler = null; scanner = null
    }

    fun isRunning() = running

    private fun schedule() {
        handler?.postDelayed({ if (running) { flush(); schedule() } }, FLUSH_MS)
    }

    /** Hand the window's accumulated sightings to the analyser as ONE session. */
    @Synchronized
    fun flush(): Int {
        if (buffer.isEmpty()) return 0
        val arr = JSONArray()
        buffer.values.forEach { arr.put(it) }
        val n = buffer.size
        buffer.clear()
        var lat = Double.NaN; var lon = Double.NaN
        try {
            val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            val loc = listOfNotNull(
                lm?.getLastKnownLocation(LocationManager.GPS_PROVIDER),
                lm?.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            ).maxByOrNull { it.time }
            if (loc != null) { lat = loc.latitude; lon = loc.longitude }
        } catch (_: SecurityException) {} catch (_: Throwable) {}
        try { watch.ingest(arr.toString(), lat, lon) } catch (_: Throwable) {}
        flushes++
        return n
    }

    fun status(): String = JSONObject()
        .put("running", running)
        .put("buffered", buffer.size)
        .put("flushes", flushes)
        .put("sightings", seenTotal)
        .apply { lastError?.let { put("error", it) } }
        .put("note", "One continuous low-power scan, harvested into ${FLUSH_MS / 1000}s windows. " +
            "Android drops scan STARTS past its limiter, so one long scan sees more than a " +
            "restart cadence would — and a tracker is best caught by steady observation over " +
            "hours, not by unpredictable timing.")
        .toString()
}
