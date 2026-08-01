package com.ant.emichaosbg

import android.webkit.JavascriptInterface
import org.json.JSONArray
import org.json.JSONObject

/**
 * BLE TRACKER / FOLLOWER DETECTION, moved out of the WebView.
 *
 * WHAT MOVED, STATED PRECISELY. The DETECTION LOGIC and the RECORD are native: the heuristics
 * run in Kotlin and findings are committed straight to [SecureLog], so a compromised page
 * cannot alter a verdict or suppress a finding, and the history survives the WebView being
 * destroyed. The SCAN TRIGGER is still page-driven — BLE scanning is orchestrated by the
 * chaotic cadence in the page, which calls ingest() with each result set.
 *
 * So this is not yet the full "runs with no WebView" property the scan engine has, and saying
 * otherwise would be a lie in a comment that outlives the memory of writing it. What it does
 * buy: the analysis and the evidence are out of the untrusted compartment, and the accumulated
 * history is too, so a page reload no longer resets what the app knows about who has been
 * following you. Moving the BLE scan cadence itself into the service is the remaining step.
 *
 * WHAT THE PAGE VERSION COULD DO, ported as-is:
 *   - Vendor fingerprints from manufacturer data (Apple Find-My, Samsung SmartTag, Tile).
 *   - MAC-ROTATION CORRELATION. Trackers rotate their MAC address to defeat naive blocklists,
 *     but the advertisement PAYLOAD often stays constant. The same payload appearing under
 *     several addresses is the rotation itself, made visible.
 *   - Advertisement-flood detection (many unique addresses in a short window).
 *
 * WHAT IT COULD NOT DO, and is the reason this is worth moving rather than copying:
 * FOLLOW DETECTION NEEDS TIME AND DISTANCE. A tracker in your bag and a tracker on a shelf you
 * walked past look identical in a single scan. They differ over minutes: the one travelling
 * with you keeps being seen, across locations far enough apart that a fixed beacon could not
 * reach both. The page could never do this — it only ran while open, so it never had the
 * history. This does:
 *
 *   - PERSISTENCE across a long window, counted in distinct scan sessions rather than raw
 *     sightings, so a device sitting still next to a beacon does not accumulate a false score.
 *   - DISPLACEMENT between first and last sighting, which is the discriminator. A beacon has a
 *     range of tens of metres; if the same identity is still with you a kilometre later, it
 *     moved with you.
 *
 * DELIBERATELY CONSERVATIVE. Your own AirTag, your own earbuds, a partner's tracker in the same
 * car, and a tag in a shared vehicle all produce a genuine follow signature — because they
 * genuinely are following you. The alert says so instead of implying malice, and both
 * thresholds must be met before anything is raised.
 */
class TrackerWatch(
    /**
     * Where findings go: (severity, message, badge). A lambda rather than a SecureLog so the
     * detection logic can be unit-tested on the JVM — SecureLog needs a real Android Context
     * and the Keystore, neither of which exists in a plain JVM test, and a heuristic that
     * decides whether to tell someone they are being followed deserves direct tests rather
     * than inference from the UI.
     */
    private val sink: (Int, String, String) -> Unit
) {

    private data class Seen(
        var firstT: Long, var lastT: Long,
        var firstLat: Double, var firstLon: Double,
        var lastLat: Double, var lastLon: Double,
        var sessions: Int, var lastSession: Long,
        var bestRssi: Int, var label: String?,
        var addrs: MutableSet<String>, var flagged: Boolean
    )

    /** Keyed by advertisement payload where available, else by address. */
    private val seen = HashMap<String, Seen>()
    private val addrWindow = ArrayList<Pair<String, Long>>()
    private var session = 0L
    private var lastFlood = 0L
    private val raised = HashMap<String, Long>()
    private val COALESCE_MS = 15 * 60_000L

    // A follow needs BOTH: seen across this many separate scan sessions, AND carried this far.
    private val MIN_SESSIONS = 6
    private val MIN_DISPLACEMENT_M = 500.0
    private val WINDOW_MS = 60 * 60_000L        // forget anything older than an hour

    private fun flag(sev: Int, key: String, what: String) {
        val now = System.currentTimeMillis()
        val prev = raised[key]
        if (prev != null && now - prev < COALESCE_MS) return
        raised[key] = now
        try { sink(sev, what, "tracker") } catch (_: Throwable) {}
    }

    /**
     * Feed one scan session's results, with the position they were seen at (NaN if no fix —
     * the persistence half still works without one, the displacement half does not).
     */
    @Synchronized
    fun ingest(devicesJson: String?, lat: Double, lon: Double): String {
        val out = JSONObject()
        val now = System.currentTimeMillis()
        session++
        val arr = try { JSONArray(devicesJson ?: "[]") } catch (_: Throwable) { JSONArray() }

        for (i in 0 until arr.length()) {
            val d = arr.optJSONObject(i) ?: continue
            val addr = d.optString("address", "")
            if (addr.isBlank()) continue
            val rssi = d.optInt("rssi", -127)

            // Vendor fingerprint from manufacturer data.
            var label: String? = null
            val mfg = d.optJSONObject("mfg")
            val payloadParts = ArrayList<String>()
            if (mfg != null) {
                val keys = mfg.keys().asSequence().toList().sorted()
                for (k in keys) {
                    val hex = mfg.optString(k, "")
                    payloadParts.add(hex)
                    val idN = k.toIntOrNull() ?: continue
                    when {
                        idN == 76 && hex.startsWith("12") -> label = "Apple Find My / AirTag"
                        idN == 117 -> label = label ?: "Samsung SmartTag"
                        idN == 224 -> label = label ?: "Chipolo"
                        idN == 89 -> label = label ?: "Nordic-based tag"
                    }
                }
            }
            val svc = d.optJSONArray("services")
            if (label == null && svc != null) {
                for (j in 0 until svc.length()) {
                    val u = svc.optString(j, "").lowercase()
                    if (u.contains("feed")) { label = "Tile"; break }
                    if (u.contains("fd5a")) { label = "Find My network"; break }
                }
            }

            // Identity key: the advertisement payload if there is one, since that is what
            // survives MAC rotation. Falls back to the address.
            val payload = payloadParts.joinToString("|")
            val key = if (payload.isNotBlank()) "p:$payload" else "a:$addr"

            val s = seen.getOrPut(key) {
                Seen(now, now, lat, lon, lat, lon, 0, -1, rssi, label, HashSet(), false)
            }
            s.lastT = now
            s.lastLat = lat; s.lastLon = lon
            if (rssi > s.bestRssi) s.bestRssi = rssi
            if (label != null) s.label = label
            s.addrs.add(addr)
            if (s.lastSession != session) { s.sessions++; s.lastSession = session }

            // MAC rotation: one payload, many addresses.
            if (s.addrs.size >= 3 && !s.flagged && payload.isNotBlank()) {
                s.flagged = true
                flag(2, "rot:$key",
                    "The same BLE advertisement has now been seen under ${s.addrs.size} different " +
                    "MAC addresses. Rotating the address while keeping the payload constant is how " +
                    "trackers avoid simple blocklists" +
                    (s.label?.let { " — this one fingerprints as $it" } ?: "") +
                    ". It may equally be your own device doing exactly what it is designed to do.")
            }

            // FOLLOW: persistent across sessions AND carried a real distance.
            if (!hasFix(lat, lon) || !hasFix(s.firstLat, s.firstLon)) continue
            val moved = metres(s.firstLat, s.firstLon, lat, lon)
            if (s.sessions >= MIN_SESSIONS && moved >= MIN_DISPLACEMENT_M) {
                val mins = ((now - s.firstT) / 60000).coerceAtLeast(1)
                flag(3, "follow:$key",
                    "A BLE device has stayed with you across ${s.sessions} separate scans over " +
                    "$mins minutes, and you have travelled ${(moved / 1000.0).let { String.format("%.1f", it) }}km " +
                    "since it was first seen" +
                    (s.label?.let { " (fingerprints as $it)" } ?: "") +
                    ". A fixed beacon reaches tens of metres, so this one moved with you. That is " +
                    "the signature of a tracker travelling in your bag, car or clothing — and it " +
                    "is also exactly what your OWN tag, your earbuds, or a tag belonging to " +
                    "someone travelling with you look like. Identify it before assuming the worst.")
            }
        }

        // Advertisement flood — many distinct addresses in a short window.
        for (i in 0 until arr.length()) {
            val a = arr.optJSONObject(i)?.optString("address", "") ?: ""
            if (a.isNotBlank()) addrWindow.add(a to now)
        }
        while (addrWindow.isNotEmpty() && now - addrWindow[0].second > 5000) addrWindow.removeAt(0)
        val uniq = addrWindow.map { it.first }.toSet().size
        if (uniq > 40 && now - lastFlood > 15000) {
            lastFlood = now
            flag(3, "ble-flood",
                "$uniq distinct BLE addresses seen within five seconds. That is far more than a " +
                "normal environment produces and is consistent with an advertisement flood — " +
                "either a denial-of-service against BLE scanning, or an attempt to bury a single " +
                "tracker's advertisements in noise so it is not noticed.")
        }

        // Forget stale identities so the map cannot grow without bound.
        val cutoff = now - WINDOW_MS
        seen.entries.removeAll { it.value.lastT < cutoff }

        return out.put("tracked", seen.size).put("session", session)
            .put("uniqueInWindow", uniq).toString()
    }

    private fun hasFix(la: Double, lo: Double) = !la.isNaN() && !lo.isNaN() && (la != 0.0 || lo != 0.0)

    private fun metres(a: Double, b: Double, c: Double, d: Double): Double {
        val R = 6371000.0
        val dLat = Math.toRadians(c - a); val dLon = Math.toRadians(d - b)
        val h = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(Math.toRadians(a)) * Math.cos(Math.toRadians(c)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2)
        return R * 2 * Math.asin(Math.sqrt(h))
    }

    @JavascriptInterface
    @Synchronized
    fun stats(): String {
        val o = JSONObject()
        o.put("tracked", seen.size)
        o.put("sessions", session)
        val followers = JSONArray()
        val now = System.currentTimeMillis()
        for ((k, s) in seen) {
            if (s.sessions < 3) continue
            val moved = if (hasFix(s.firstLat, s.firstLon) && hasFix(s.lastLat, s.lastLon))
                metres(s.firstLat, s.firstLon, s.lastLat, s.lastLon) else 0.0
            followers.put(JSONObject()
                .put("id", k.take(24))
                .put("label", s.label ?: "unidentified")
                .put("sessions", s.sessions)
                .put("addresses", s.addrs.size)
                .put("minutes", (now - s.firstT) / 60000)
                .put("movedM", moved.toInt())
                .put("rssi", s.bestRssi)
                .put("following", s.sessions >= MIN_SESSIONS && moved >= MIN_DISPLACEMENT_M))
        }
        o.put("candidates", followers)
        o.put("note", "A follow needs BOTH persistence across separate scans AND real displacement " +
            "— a tracker on a shelf you walked past cannot produce both. Your own tag and a " +
            "companion's tag produce them legitimately, because they are genuinely travelling " +
            "with you.")
        return o.toString()
    }
}
