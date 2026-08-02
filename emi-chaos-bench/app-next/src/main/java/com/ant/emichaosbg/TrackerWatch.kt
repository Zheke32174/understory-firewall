package com.ant.emichaosbg

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
        var addrs: MutableSet<String>, var flagged: Boolean,
        /** Separate latch from [flagged]: camped and rotating are different findings. */
        var campFlagged: Boolean = false
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

    // CAMPED: the stationary-user complement to a follow. Higher session count and a real time
    // span, because at zero displacement persistence is the only evidence there is.
    private val MIN_CAMP_SESSIONS = 12
    private val MIN_CAMP_MINUTES = 15L
    private val STATIONARY_M = 75.0             // inside GNSS noise for a phone sitting still

    /**
     * BLE ADDRESS PRIVACY CLASS, from the two most significant bits of the first octet.
     *
     * This is the discriminator that turns "an unidentified device has been here 25 minutes"
     * into something a person can act on. Bluetooth LE privacy exists precisely so that devices
     * do NOT keep one address: a modern phone, watch, or earbud uses a Resolvable Private
     * Address and rotates it roughly every 15 minutes, which is why a scan of a busy room
     * produces churn rather than a stable roster.
     *
     * A device that holds ONE address for half an hour is therefore not doing what current
     * consumer hardware does. That is not proof of anything hostile — fixed infrastructure,
     * beacons, older peripherals, and plenty of embedded gear use static addresses because
     * they were built before the privacy spec or have no reason to hide. But it separates
     * "phone that walked past" from "thing that is installed here", and that separation is the
     * whole question when the user is stationary and asking what is parked around them.
     *
     *   0b11 → random STATIC     — random-looking, but fixed for the device's lifetime
     *   0b01 → resolvable private — the privacy-preserving default; rotates
     *   0b00 → non-resolvable private — rotates, rare
     *   otherwise → public        — a real vendor OUI, permanently fixed and attributable
     */
    private fun addrClass(addr: String): String {
        val first = addr.substringBefore(':').toIntOrNull(16) ?: return "unknown"
        return when (first ushr 6) {
            0b11 -> "random-static"
            0b01 -> "resolvable-private"
            0b00 -> "non-resolvable-private"
            else -> "public"
        }
    }

    /** True when the address is one that is SUPPOSED to rotate. */
    private fun rotatesByDesign(addr: String) =
        addrClass(addr).endsWith("private")

    /**
     * VENDOR FROM THE ADVERTISEMENT, WITHOUT CONNECTING TO ANYTHING.
     *
     * The key of the manufacturer-specific data block IS the Bluetooth SIG company identifier —
     * it was already being captured and used only as an opaque fingerprint. Decoding it turns a
     * row reading "unidentified · 25 min · moved 0m" into a named manufacturer, which is the
     * difference between a list a person can triage and a list they can only stare at. A
     * stationary user looking at 41 unknown emitters cannot act on any of them; the same 41
     * split into "your TV's vendor", "a laptop vendor" and "three I cannot name" is a shortlist.
     *
     * Entirely PASSIVE. This reads a field already present in advertisements the radio was
     * receiving anyway — no connection, no GATT, no probe, nothing transmitted. Identifying a
     * device by connecting to it would announce your interest to whoever owns it, which for
     * someone investigating what is parked around them is exactly the wrong trade.
     *
     * Only IDs I am confident of are named; anything else is reported as its hex ID rather than
     * guessed at, because a wrong vendor name is worse than an honest number.
     */
    private fun vendorOf(companyId: Int): String? = when (companyId) {
        0x004C -> "Apple"
        0x0006 -> "Microsoft"
        0x0075 -> "Samsung"
        0x00E0 -> "Google"
        0x0059 -> "Nordic Semiconductor"
        0x02E5 -> "Espressif (ESP32)"
        0x0087 -> "Garmin"
        0x000F -> "Broadcom"
        0x000D -> "Texas Instruments"
        0x0001 -> "Ericsson"
        0x0157 -> "Huami / Amazfit"
        0x0171 -> "Amazon"
        0x0499 -> "Ruuvi"
        0x0310 -> "SGL Italia"
        else -> null
    }

    /** Human label for a sighting's manufacturer block, or null when it carries none. */
    private fun describeVendor(o: JSONObject): String? {
        val mfg = o.optJSONObject("mfg") ?: return null
        val k = mfg.keys()
        if (!k.hasNext()) return null
        val idStr = k.next()
        val id = idStr.toIntOrNull() ?: return null
        return vendorOf(id) ?: "company 0x%04x".format(id)
    }

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
            // The advertised device NAME, when one is broadcast, beats any inference.
            if (label == null) d.optString("name", "").takeIf { it.isNotBlank() }
                ?.let { label = "\"$it\"" }
            // Otherwise fall back to the manufacturer, so a row is attributable to a company
            // even when the exact product cannot be named. "unidentified" was doing a lot of
            // work in that list: 41 rows of it is not triageable, and the company ID needed to
            // fix that was already in the advertisement, unused.
            if (label == null) describeVendor(d)?.let { label = it }

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

            /* CAMPED: persistent NEXT TO YOU while you are not moving.
             *
             * THE GAP THIS CLOSES. The follow test below requires real displacement, on the
             * sound reasoning that a tracker in your bag and a beacon on a shelf are identical
             * in one sweep and only separable by movement. But that makes displacement a
             * NECESSARY condition — so for a user who does not move, the panel can only ever
             * say "nothing following", however long something sits beside them. Observed
             * exactly that on device: 41 identities, 1551 sightings, 77 scan sessions, almost
             * every entry reading "moved 0m", and a confident "nothing following". That is a
             * structural false all-clear in the one situation where a person at home, who
             * suspects something is parked nearby, most needs an answer.
             *
             * Being stationary does not remove the question, it changes it: not "is this
             * travelling with me" but "has this been sitting on me for a long time". So a
             * device seen across many sessions, over a long span, while the DEVICE ITSELF has
             * not moved, is reported as CAMPED.
             *
             * Deliberately weaker language and a lower severity than a follow. A camped BLE
             * device is overwhelmingly likely to be a neighbour's TV, a thermostat, a smart
             * bulb, a car in the driveway, or your own hardware — anything mains-powered and
             * stationary looks exactly like this. It is reported because "we cannot tell you
             * anything while you sit still" is worse than a hedged answer, not because it is
             * damning.
             */
            val stationary = hasFix(lat, lon) && hasFix(s.firstLat, s.firstLon) &&
                metres(s.firstLat, s.firstLon, lat, lon) < STATIONARY_M
            val spanMin = (now - s.firstT) / 60000
            if (!s.campFlagged && s.sessions >= MIN_CAMP_SESSIONS && spanMin >= MIN_CAMP_MINUTES &&
                (stationary || !hasFix(lat, lon))) {
                s.campFlagged = true
                val stableMac = s.addrs.size == 1
                flag(2, "camp:$key",
                    "A BLE device has been within range across ${s.sessions} separate scans over " +
                    "$spanMin minutes while you have not moved" +
                    (s.label?.let { " (fingerprints as $it)" } ?: "") +
                    ", strongest signal ${s.bestRssi}dBm." +
                    (if (stableMac)
                        " It has held ONE MAC address the whole time — most modern devices rotate " +
                        "theirs every few minutes for privacy, so a stable address means rotation " +
                        "is disabled, absent, or the device predates it."
                     else "") +
                    " This is NOT the tracker-following-you test, which needs you to travel; it " +
                    "is the complement, for when you are stationary. Anything mains-powered " +
                    "nearby looks like this — a TV, a thermostat, a bulb, a parked car, your own " +
                    "hardware. It is listed so that a persistent emitter is visible to you at " +
                    "all, rather than hidden behind a movement test you cannot satisfy.")
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
            val mins = (now - s.firstT) / 60000
            val anyAddr = s.addrs.firstOrNull()
            val cls = anyAddr?.let { addrClass(it) } ?: "unknown"
            // "Static" here means: one address, held the whole time, of a kind that is NOT
            // supposed to rotate. That is the property that separates installed infrastructure
            // from phones walking past, and it is the only handle a stationary user has.
            val staticAddr = s.addrs.size == 1 && anyAddr != null && !rotatesByDesign(anyAddr)
            followers.put(JSONObject()
                .put("id", k.take(24))
                .put("label", s.label ?: "unidentified")
                .put("sessions", s.sessions)
                .put("addresses", s.addrs.size)
                .put("minutes", mins)
                .put("movedM", moved.toInt())
                .put("rssi", s.bestRssi)
                .put("addrClass", cls)
                .put("staticAddr", staticAddr)
                .put("camped", s.sessions >= MIN_CAMP_SESSIONS && mins >= MIN_CAMP_MINUTES &&
                    moved < STATIONARY_M)
                .put("following", s.sessions >= MIN_SESSIONS && moved >= MIN_DISPLACEMENT_M))
        }
        o.put("candidates", followers)
        o.put("note", "A FOLLOW needs BOTH persistence across separate scans AND real " +
            "displacement — a tracker on a shelf you walked past cannot produce both. Your own " +
            "tag and a companion's tag produce them legitimately, because they are genuinely " +
            "travelling with you.\n\n" +
            "CAMPED is the complement, and it exists because displacement is a NECESSARY " +
            "condition for a follow: a user who does not move can never satisfy it, so the " +
            "panel could only ever report 'nothing following' however long something sat beside " +
            "them. Camped means many sessions over a long span while you stayed put. " +
            "STATIC ADDRESS means one address held throughout, of a type that is not supposed " +
            "to rotate — modern phones and wearables use resolvable private addresses and change " +
            "them every few minutes, so a fixed address is the signature of installed equipment " +
            "rather than someone passing by. Neither is an accusation: everything mains-powered " +
            "nearby looks exactly like this.")
        return o.toString()
    }
}
