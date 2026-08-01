package com.ant.emichaosbg

import org.json.JSONObject

/**
 * THE SINGLE OWNER OF `WifiManager.startScan()`.
 *
 * THE BUG THIS FIXES. Android allows roughly four scan STARTS per two minutes per app and
 * silently ignores the rest — an over-eager scanner does not see more, it just gets dropped
 * while still costing power. The page had a careful accountant for that: a rolling window, a
 * cap of four, and two slots deliberately reserved for wardriving so a background sweep could
 * not starve the thing the user actually asked for.
 *
 * Then the native ScanEngine was added and called startScan() every 18-46 seconds on its own
 * timer, outside that accounting entirely. Roughly 3.75 starts per two minutes — very nearly
 * the whole platform budget — spent by a component the page's accountant did not know existed.
 * The consequences were exactly what was reported: wardriving's reserved slots were consumed
 * by something else, the page believed it had four slots when it had none, and BOTH sides
 * reported "scanning normally" while the platform threw most of the requests away. A budget
 * that only one of two callers respects is not a budget.
 *
 * So the gate moved here, below both of them. EmiBridge.wifiScan() and ScanEngine now ask the
 * same object, and it is the only thing in the app that calls startScan().
 *
 * WHY DENIAL IS CHEAP. Only the START is throttled; reading `wm.scanResults` is free and
 * returns the platform's cache. So a denied request still returns real, recent results — it
 * simply does not ask the radio for a fresh sweep. That is why refusing here costs almost
 * nothing, and why asking anyway would cost power for data the caller already had.
 *
 * PRIORITY. 'critical' (wardriving, an explicit user press) may use the last two slots;
 * background sweeps may not. That reservation is the reason the whole mechanism exists, and it
 * only works if there is one ledger.
 */
object WifiScanBudget {

    private const val WINDOW_MS = 120_000L
    private const val MAX_STARTS = 4
    private const val RESERVED_FOR_CRITICAL = 2

    private val stamps = ArrayList<Long>()
    private var granted = 0L
    private var denied = 0L
    private var lastDeniedCaller: String? = null

    /**
     * @return true if the caller may invoke startScan() right now. Callers MUST read
     *   `wm.scanResults` regardless — a denial means "do not ask the radio", not "no data".
     */
    @Synchronized
    fun tryStart(priority: String, caller: String): Boolean {
        val now = System.currentTimeMillis()
        while (stamps.isNotEmpty() && now - stamps[0] > WINDOW_MS) stamps.removeAt(0)
        val room = MAX_STARTS - stamps.size
        if (room <= 0) { denied++; lastDeniedCaller = caller; return false }
        if (priority != "critical" && room <= RESERVED_FOR_CRITICAL) {
            // Background sweep asking for a slot that is being held for a user-facing scan.
            denied++; lastDeniedCaller = caller; return false
        }
        stamps.add(now); granted++
        return true
    }

    @Synchronized
    fun state(): String {
        val now = System.currentTimeMillis()
        while (stamps.isNotEmpty() && now - stamps[0] > WINDOW_MS) stamps.removeAt(0)
        val o = JSONObject()
            .put("used", stamps.size)
            .put("max", MAX_STARTS)
            .put("reserved", RESERVED_FOR_CRITICAL)
            .put("granted", granted)
            .put("denied", denied)
        lastDeniedCaller?.let { o.put("lastDenied", it) }
        // When the window is full, say when a slot frees. "Throttled" with no horizon reads as
        // broken; "a slot frees in 34s" reads as working within a known limit.
        if (stamps.isNotEmpty() && stamps.size >= MAX_STARTS)
            o.put("freesInMs", (WINDOW_MS - (now - stamps[0])).coerceAtLeast(0))
        o.put("note", "Android allows about $MAX_STARTS scan STARTS per two minutes per app and " +
            "drops the rest silently. Reading cached results is free and unaffected, so a denied " +
            "start still returns recent data — it just does not spin the radio. " +
            "$RESERVED_FOR_CRITICAL slots are held for wardriving and explicit scans so a " +
            "background sweep cannot starve them.")
        return o.toString()
    }
}
