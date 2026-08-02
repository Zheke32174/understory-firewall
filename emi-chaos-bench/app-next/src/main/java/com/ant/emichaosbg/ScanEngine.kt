package com.ant.emichaosbg

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.HandlerThread
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

/**
 * NATIVE scan + detection + alerting. This is the subsystem moving out of the WebView.
 *
 * WHY. The WebView is the untrusted compartment: it is where injected script would land, and
 * it is destroyed the moment the Activity goes away. Until now the radio READS were native
 * (EmiBridge) but the CADENCE, the DETECTION HEURISTICS and the ALERT RAISING all lived in
 * page JavaScript. That put the three things that matter most — whether a scan happened, what
 * it concluded, and whether the conclusion was recorded — inside the one component that
 * anything hostile reaches first and that the OS discards first.
 *
 * WHAT CHANGES. This class owns its own thread and its own cadence, runs the Wi-Fi and BLE
 * detection heuristics in Kotlin, and commits every finding STRAIGHT INTO [SecureLog] with
 * source="native" before the WebView is told anything. The page becomes a viewer over
 * [snapshot]. Three concrete consequences:
 *
 *   1. Findings are recorded even with no WebView alive at all — the foreground service keeps
 *      this running after the app is swiped off recents.
 *   2. A page compromised badly enough to stop calling EMIVault.append cannot suppress a
 *      finding, because it was never the thing doing the appending.
 *   3. The evidence for a detection is committed BEFORE it is displayed, so a crash between
 *      detecting and rendering loses the pixel, not the record.
 *
 * WHAT DOES NOT CHANGE. Everything here still reports and nothing blocks. No transmit, no
 * jamming, no beacon advertising, no active probing — Wi-Fi results come from the platform's
 * own scan cache and BLE is passive enumeration. A false positive costs a notification, never
 * a masking session. The heuristics are hints to go look closer, not certified detection, and
 * they are worded that way in the alerts themselves.
 *
 * THROTTLE HONESTY. Android allows ~4 Wi-Fi scans per 2 minutes per app and silently drops the
 * rest — an over-eager scanner does not scan more, it just gets ignored while still costing
 * power. The cadence here respects that budget rather than pretending to beat it, and reports
 * what it actually got (see [snapshot]).
 */
class ScanEngine(private val ctx: Context, private val log: SecureLog) {

    @Volatile private var running = false
    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    // Per-BSSID and per-SSID memory, used to tell "new" from "seen before".
    private val seenBssid = HashMap<String, Long>()
    private val ssidToOui = HashMap<String, MutableSet<String>>()
    private var lastWifi = JSONArray()
    private var wifiScans = 0L
    private var findings = 0L
    private var lastScanAt = 0L
    private var lastError: String? = null

    // Alert coalescing, native side. Same intent as the page's: an identical finding repeating
    // every scan cycle must not consume the log. Keyed by badge+message.
    private val lastRaised = HashMap<String, Long>()
    private val COALESCE_MS = 120_000L

    fun start() {
        if (running) return
        running = true
        val t = HandlerThread("emi-scan").also { it.start() }
        thread = t
        handler = Handler(t.looper)
        schedule(1_500)
    }

    fun stop() {
        running = false
        handler?.removeCallbacksAndMessages(null)
        try { thread?.quitSafely() } catch (_: Exception) {}
        thread = null; handler = null
    }

    fun isRunning() = running

    /**
     * Chaotic but budget-respecting cadence. The interval is randomised so the scan pattern is
     * not a metronome an observer could predict, but its MEAN is held at roughly the platform
     * budget (4 per 2 min = one per 30s) rather than above it. Asking faster than the budget
     * does not produce more data; it produces the same data plus wasted radio power and a
     * silently-dropped request.
     */
    private fun schedule(delayMs: Long) {
        val h = handler ?: return
        h.postDelayed({ if (running) { tick(); schedule(nextGap()) } }, delayMs)
    }

    private fun nextGap(): Long {
        // 18s..46s, mean ~32s — just under the 30s-per-slot budget, with jitter.
        return (18_000 + (Math.random() * 28_000)).toLong()
    }

    private fun tick() {
        try {
            val list = wifiScanNative()
            lastWifi = list
            wifiScans++
            lastScanAt = System.currentTimeMillis()
            analyseWifi(list)
            lastError = null
        } catch (e: Throwable) {
            lastError = e.javaClass.simpleName + ": " + (e.message ?: "")
        }
    }

    // ---------------------------------------------------------------- Wi-Fi

    private fun wifiScanNative(): JSONArray {
        val arr = JSONArray()
        val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return arr
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) return arr
        // Through the shared gate. This engine is a BACKGROUND sweep, so it never takes the
        // slots reserved for wardriving and explicit user scans — that reservation was being
        // silently consumed before the gate existed.
        if (WifiScanBudget.tryStart("background", "ScanEngine")) {
            try { wm.startScan() } catch (_: Exception) { /* platform refused; cache below */ }
        }
        // Cached results are read either way: only the START is throttled, so a denial costs
        // freshness, not data.
        @Suppress("DEPRECATION")
        for (r in wm.scanResults) {
            val o = JSONObject()
            o.put("ssid", r.SSID ?: ""); o.put("bssid", r.BSSID ?: "")
            o.put("level", r.level); o.put("freq", r.frequency)
            o.put("caps", r.capabilities ?: "")
            arr.put(o)
        }
        return arr
    }

    /**
     * The detection heuristics, in Kotlin. Each one aggregates across the WHOLE scan before
     * raising anything — the page version's original sin was raising one alert per matching
     * network, which flooded a 60-entry log with three copies of the same finding per cycle.
     */
    private fun analyseWifi(list: JSONArray) {
        var open = 0; var wps = 0; var hidden = 0
        val ssidVendors = HashMap<String, MutableSet<String>>()
        val ssidBssidCount = HashMap<String, MutableSet<String>>()

        for (i in 0 until list.length()) {
            val o = list.optJSONObject(i) ?: continue
            val ssid = o.optString("ssid", "")
            val bssid = o.optString("bssid", "").lowercase()
            val caps = o.optString("caps", "")

            if (ssid.isBlank()) hidden++
            // "Open" means no link-layer confidentiality at all. WEP is counted with it because
            // WEP is break-in-minutes, not security — but they are named separately in the text
            // so the report stays accurate about which was seen.
            val isOpen = !caps.contains("WPA") && !caps.contains("RSN") && !caps.contains("SAE")
            if (isOpen) open++
            if (caps.contains("WPS")) wps++

            if (ssid.isNotBlank() && bssid.length >= 8) {
                val oui = bssid.substring(0, 8)          // vendor prefix
                ssidVendors.getOrPut(ssid) { HashSet() }.add(oui)
                ssidBssidCount.getOrPut(ssid) { HashSet() }.add(bssid)
                ssidToOui.getOrPut(ssid) { HashSet() }.add(oui)
            }
            if (bssid.isNotBlank()) seenBssid[bssid] = System.currentTimeMillis()
        }

        if (open > 0) raise(1, "$open nearby network${s(open)} ${isAre(open)} open or WEP-secured — " +
            "traffic there isn't protected by the network itself.", "open-net")
        if (wps > 0) raise(1, "$wps nearby network${s(wps)} advertise${if (wps == 1) "s" else ""} WPS — " +
            "a known-weak pairing mode (WPS PIN brute-force).", "wps")
        if (hidden > 2) raise(0, "$hidden nearby networks are broadcasting no SSID. Common enough to be " +
            "unremarkable on its own; noted only because it is a cheap way to be less visible.", "hidden")

        // Rogue / evil-twin: ONE SSID appearing under several different VENDOR prefixes. A
        // legitimate multi-AP network almost always buys its hardware from one vendor, so
        // several vendors behind one name is the interesting shape. Reported as ambiguous
        // because a genuine mixed-vendor mesh or a replaced AP produces it too.
        for ((ssid, vendors) in ssidVendors) {
            if (vendors.size >= 2) {
                raise(2, "Wi-Fi SSID \"$ssid\" is broadcast from ${vendors.size} different vendor MAC " +
                    "prefixes — possible rogue/evil-twin AP, or a legitimate mixed-vendor mesh. " +
                    "Ambiguous on its own; worth checking if you don't recognise this network.", "rogue-ap")
            }
        }
        // Karma-style: one name on many radios at once, beyond what a normal mesh runs.
        for ((ssid, bssids) in ssidBssidCount) {
            if (bssids.size >= 6) {
                raise(2, "Wi-Fi SSID \"$ssid\" answers on ${bssids.size} distinct BSSIDs simultaneously — " +
                    "more radios than a typical mesh. Can indicate a Karma-style responder that " +
                    "answers to any probed name. Heuristic; large venues do this legitimately.", "karma")
            }
        }
    }

    private fun s(n: Int) = if (n == 1) "" else "s"
    private fun isAre(n: Int) = if (n == 1) "is" else "are"

    /**
     * Commit first, count second. The SecureLog append is the record; the counter is only a
     * readout. Coalesced so a finding that is true every cycle is logged once per window
     * rather than once per scan.
     */
    private fun raise(sev: Int, msg: String, badge: String) {
        val key = "$badge|$msg"
        val now = System.currentTimeMillis()
        val prev = lastRaised[key]
        if (prev != null && now - prev < COALESCE_MS) return
        lastRaised[key] = now
        /* COUNT WHAT WAS ACTUALLY STORED. append() RETURNS a Boolean and this discarded it,
         * incrementing `findings` whether or not the record reached the vault. On the device
         * whose log stopped accepting readable records, the panel therefore kept counting up
         * findings that could never be read back — the number on screen and the evidence on
         * disk diverged silently, which is the one thing a counter-surveillance readout must
         * not do. Failures are now counted separately and surfaced, so "we found 40 things"
         * and "we stored 40 things" can be compared. */
        val stored = try { log.append(sev, msg, badge, "native") } catch (_: Throwable) { false }
        if (stored) findings++ else notStored++
    }

    /** Findings that were raised but did NOT reach the vault. Surfaced in [snapshot]. */
    @Volatile private var notStored = 0

    // ---------------------------------------------------------------- readout

    /** Everything the page needs to RENDER this, and nothing it needs to run it. */
    fun snapshot(): String {
        val o = JSONObject()
        o.put("running", running)
        if (notStored > 0) {
            o.put("notStored", notStored)
            o.put("storeWarning", "$notStored finding(s) were detected but could NOT be written " +
                "to the encrypted log. What you see here is not fully backed by stored evidence.")
        }
        o.put("wifiScans", wifiScans)
        o.put("findings", findings)
        o.put("lastScanAt", lastScanAt)
        o.put("networks", lastWifi.length())
        o.put("knownBssids", seenBssid.size)
        lastError?.let { o.put("error", it) }
        // Why nothing is being found, when nothing is being found. Same reasoning as the
        // wardrive reason line: the master location switch starves Wi-Fi scanning outright,
        // and reporting "0 networks" instead of naming it sends you looking at the radio.
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        val locOn = try { lm?.isLocationEnabled ?: true } catch (_: Throwable) { true }
        val fine = ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        o.put("locationEnabled", locOn)
        o.put("fineLocation", fine)
        o.put("why", when {
            !running -> "native scan engine is not running"
            !locOn -> "DEVICE LOCATION IS OFF — Android returns zero Wi-Fi scan results while it is " +
                "off, whatever permissions this app holds"
            !fine -> "precise-location permission not granted — Android withholds scan results without it"
            lastWifi.length() == 0 -> "scans running but returning zero networks"
            else -> "scanning normally"
        })
        return o.toString()
    }

    fun lastWifiJson(): String = lastWifi.toString()
}
