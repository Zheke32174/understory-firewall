package com.ant.emichaosbg

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.telephony.*
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.*

/**
 * TOWER + POSITION MEASUREMENT LOG — Tower Collector and GPSLogger, ported rootless.
 *
 * Tower Collector records "which cell was I attached to, where, and how strongly". GPSLogger
 * records position on a schedule with an accuracy filter and exports it in the formats mapping
 * tools actually read. Both are rootless already; this is a port, not a lesser form.
 *
 * WHY IT BELONGS IN THIS APP RATHER THAN BESIDE IT. The cellular heuristics in [CellSecurity]
 * work on what is visible RIGHT NOW — one sample, no memory. Half of what makes an IMSI
 * catcher visible only exists across time and space: a cell that appears in one place and
 * never again, a cell ID that shows up at two locations kilometres apart, a tower that is
 * present for twenty minutes and then gone. None of that is detectable from a single reading.
 * This is the record that makes those questions answerable, and it feeds two detections that
 * the live checks cannot make on their own:
 *
 *   - THE SAME CELL SEEN AT IMPOSSIBLE DISTANCES. A real macro cell has a fixed location, so
 *     the same identity appearing far from where it was first logged means either the identity
 *     is being cloned or something mobile is carrying it.
 *   - A CELL THAT NEVER REAPPEARS on ground you cover often. Real infrastructure is persistent;
 *     equipment brought to a place for a while is not.
 *
 * PRIVACY. This log DOES contain location, unavoidably — a position log without positions is
 * nothing. That is exactly why it is kept OUT of the encrypted alert vault, which is
 * deliberately location-free: the vault is the file most worth stealing, and mixing a movement
 * history into it would ruin that property. This is a separate store the user exports
 * deliberately, and it is the one part of the app that should be treated as sensitive on its
 * own terms. Nothing is uploaded; there is no server to upload to. Tower Collector's
 * OpenCelliD submission is deliberately NOT ported — an app that quietly uploads a
 * counter-surveillance user's movements would be self-defeating.
 */
class TowerLog(private val ctx: Context) {

    data class Fix(
        val t: Long, val lat: Double, val lon: Double, val acc: Float,
        val alt: Double, val speed: Float, val bearing: Float,
        val gen: Int, val kind: String, val cid: Long, val area: Int,
        val mcc: String, val mnc: String, val dbm: Int, val neighbours: Int
    )

    private val fixes = ArrayList<Fix>()
    private val MAX = 20000                 // ~ a few MB; beyond this the oldest go
    private var lastAt = 0L
    private var lastLat = Double.NaN
    private var lastLon = Double.NaN

    // GPSLogger's two triggers plus its accuracy gate. Either trigger can fire a record; the
    // accuracy gate rejects fixes too vague to be worth storing, which is what stops a log
    // filling with 2km-radius network fixes while indoors.
    @Volatile var minIntervalMs = 30_000L
    @Volatile var minDistanceM = 25.0
    @Volatile var maxAccuracyM = 100.0
    @Volatile var running = false

    /** Cell identities and where they were first seen, for the cross-time detections. */
    private val cellFirstSeen = HashMap<String, Triple<Double, Double, Long>>()
    private val cellCount = HashMap<String, Int>()

    fun start(): Boolean { running = true; return true }
    fun stop(): Boolean { running = false; return false }
    fun isRunning(): Boolean = running

    fun configure(intervalSec: Int, distanceM: Int, accuracyM: Int): String {
        minIntervalMs = (intervalSec.coerceIn(1, 3600)).toLong() * 1000L
        minDistanceM = distanceM.coerceIn(0, 5000).toDouble()
        maxAccuracyM = accuracyM.coerceIn(5, 5000).toDouble()
        return JSONObject().put("intervalSec", minIntervalMs / 1000)
            .put("distanceM", minDistanceM).put("accuracyM", maxAccuracyM).toString()
    }

    /**
     * Takes one measurement if the triggers allow. Called on the service cadence, so logging
     * continues with the app backgrounded — the case that matters, since a phone in a pocket
     * is exactly when you are moving past towers.
     */
    @Synchronized
    fun tick(): String {
        val o = JSONObject()
        if (!running) return o.put("logged", false).put("why", "not running").toString()
        val fine = ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        if (!fine) return o.put("logged", false).put("why", "location permission not granted").toString()

        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return o.put("logged", false).put("why", "no LocationManager").toString()
        val loc: Location? = try {
            listOfNotNull(
                lm.getLastKnownLocation(LocationManager.GPS_PROVIDER),
                lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            ).maxByOrNull { it.time }
        } catch (_: SecurityException) { null } catch (_: Throwable) { null }

        if (loc == null) return o.put("logged", false).put("why", "no fix yet").toString()
        if (loc.accuracy > maxAccuracyM)
            return o.put("logged", false)
                .put("why", "fix accuracy ${loc.accuracy.toInt()}m worse than the ${maxAccuracyM.toInt()}m gate")
                .toString()

        val now = System.currentTimeMillis()
        val movedEnough = if (lastLat.isNaN()) true
            else metres(lastLat, lastLon, loc.latitude, loc.longitude) >= minDistanceM
        val waitedEnough = now - lastAt >= minIntervalMs
        if (!movedEnough && !waitedEnough)
            return o.put("logged", false).put("why", "neither trigger met").toString()

        // Cell state at this position.
        var gen = 0; var kind = "none"; var cid = -1L; var area = -1
        var mcc = ""; var mnc = ""; var dbm = Int.MIN_VALUE; var neighbours = 0
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_PHONE_STATE) ==
            PackageManager.PERMISSION_GRANTED) {
            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            val cells = try { tm?.allCellInfo ?: emptyList() } catch (_: Throwable) { emptyList() }
            for (c in cells) {
                if (!c.isRegistered) { neighbours++; continue }
                when (c) {
                    is CellInfoLte -> { gen = 4; kind = "LTE"
                        cid = c.cellIdentity.ci.toLong(); area = c.cellIdentity.tac
                        dbm = c.cellSignalStrength.dbm
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            mcc = c.cellIdentity.mccString ?: ""; mnc = c.cellIdentity.mncString ?: "" } }
                    is CellInfoGsm -> { gen = 2; kind = "GSM"
                        cid = c.cellIdentity.cid.toLong(); area = c.cellIdentity.lac
                        dbm = c.cellSignalStrength.dbm
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            mcc = c.cellIdentity.mccString ?: ""; mnc = c.cellIdentity.mncString ?: "" } }
                    is CellInfoWcdma -> { gen = 3; kind = "WCDMA"
                        cid = c.cellIdentity.cid.toLong(); area = c.cellIdentity.lac
                        dbm = c.cellSignalStrength.dbm
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            mcc = c.cellIdentity.mccString ?: ""; mnc = c.cellIdentity.mncString ?: "" } }
                    else -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && c is CellInfoNr) {
                        gen = 5; kind = "NR"
                        val id = c.cellIdentity as? CellIdentityNr
                        cid = id?.nci ?: -1L; area = id?.tac ?: -1
                        mcc = id?.mccString ?: ""; mnc = id?.mncString ?: ""
                        dbm = c.cellSignalStrength.dbm }
                }
            }
        }

        fixes.add(Fix(now, loc.latitude, loc.longitude, loc.accuracy,
            if (loc.hasAltitude()) loc.altitude else Double.NaN,
            if (loc.hasSpeed()) loc.speed else Float.NaN,
            if (loc.hasBearing()) loc.bearing else Float.NaN,
            gen, kind, cid, area, mcc, mnc, dbm, neighbours))
        while (fixes.size > MAX) fixes.removeAt(0)
        lastAt = now; lastLat = loc.latitude; lastLon = loc.longitude

        // Cross-time analysis — the part a single live reading cannot do.
        var anomaly: String? = null
        if (cid > 0) {
            val key = "$kind:$mcc-$mnc:$cid"
            cellCount[key] = (cellCount[key] ?: 0) + 1
            val first = cellFirstSeen[key]
            if (first == null) cellFirstSeen[key] = Triple(loc.latitude, loc.longitude, now)
            else {
                val d = metres(first.first, first.second, loc.latitude, loc.longitude)
                // A macro cell reaches at most ~35km in the best case and far less in practice.
                // The same identity 35km from where it was first logged is not one tower.
                if (d > 35000) anomaly =
                    "Cell $key has now been logged ${(d / 1000).toInt()}km from where it was first " +
                    "seen. A fixed tower cannot be in two places — either the identity is being " +
                    "reused by different equipment, or something carrying that identity is mobile. " +
                    "Carrier reconfiguration also recycles cell IDs, so check the dates before " +
                    "concluding."
            }
        }
        anomaly?.let { o.put("anomaly", it) }

        return o.put("logged", true).put("count", fixes.size)
            .put("lat", loc.latitude).put("lon", loc.longitude)
            .put("accuracy", loc.accuracy).put("cell", cid).put("gen", gen)
            .put("dbm", if (dbm == Int.MIN_VALUE) JSONObject.NULL else dbm)
            .toString()
    }

    private fun metres(a: Double, b: Double, c: Double, d: Double): Double {
        val R = 6371000.0
        val dLat = Math.toRadians(c - a); val dLon = Math.toRadians(d - b)
        val h = sin(dLat / 2).pow(2) + cos(Math.toRadians(a)) * cos(Math.toRadians(c)) * sin(dLon / 2).pow(2)
        return R * 2 * asin(sqrt(h))
    }

    fun stats(): String {
        val o = JSONObject()
        o.put("running", running).put("fixes", fixes.size)
        o.put("uniqueCells", cellFirstSeen.size)
        o.put("intervalSec", minIntervalMs / 1000).put("distanceM", minDistanceM)
        o.put("accuracyGateM", maxAccuracyM)
        fixes.lastOrNull()?.let {
            o.put("lastAt", it.t).put("lastCell", it.cid).put("lastGen", it.gen)
            o.put("lastAcc", it.acc)
        }
        // Cells seen exactly once are the interesting tail — persistent infrastructure repeats.
        o.put("singletonCells", cellCount.values.count { it == 1 })
        return o.toString()
    }

    // ---- exports. Location-bearing, so each is an explicit user action. -------------------

    fun exportGpx(): String {
        val sb = StringBuilder()
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            .append("<gpx version=\"1.1\" creator=\"EMI Chaos Bench\" xmlns=\"http://www.topografix.com/GPX/1/1\">\n")
            .append("<trk><name>tower log</name><trkseg>\n")
        val iso = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
        for (f in fixes) {
            sb.append("<trkpt lat=\"").append(f.lat).append("\" lon=\"").append(f.lon).append("\">")
            if (!f.alt.isNaN()) sb.append("<ele>").append(f.alt).append("</ele>")
            sb.append("<time>").append(iso.format(java.util.Date(f.t))).append("</time>")
            sb.append("<desc>").append(esc("${f.kind} cid=${f.cid} tac=${f.area} " +
                "${f.mcc}-${f.mnc} ${f.dbm}dBm acc=${f.acc}m")).append("</desc>")
            sb.append("</trkpt>\n")
        }
        sb.append("</trkseg></trk></gpx>\n")
        return sb.toString()
    }

    /** KML, which GPSLogger emits and every mapping tool opens. */
    fun exportKml(): String {
        val sb = StringBuilder()
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            .append("<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>\n")
            .append("<name>EMI Chaos Bench tower log</name>\n")
        // The path itself.
        sb.append("<Placemark><name>track</name><LineString><tessellate>1</tessellate>")
            .append("<coordinates>\n")
        for (f in fixes) sb.append(f.lon).append(',').append(f.lat).append(',')
            .append(if (f.alt.isNaN()) 0.0 else f.alt).append('\n')
        sb.append("</coordinates></LineString></Placemark>\n")
        // One pin per distinct cell, at where it was first seen — the useful view for
        // spotting a tower that only ever existed in one spot.
        for ((key, v) in cellFirstSeen) {
            sb.append("<Placemark><name>").append(esc(key)).append("</name>")
                .append("<description>").append(esc("seen ${cellCount[key] ?: 1} time(s)"))
                .append("</description>")
                .append("<Point><coordinates>").append(v.second).append(',').append(v.first)
                .append(",0</coordinates></Point></Placemark>\n")
        }
        sb.append("</Document></kml>\n")
        return sb.toString()
    }

    fun exportCsv(): String {
        val sb = StringBuilder()
        sb.append("timestamp_iso,epoch_ms,lat,lon,accuracy_m,altitude_m,speed_mps,bearing_deg,")
            .append("rat,generation,cell_id,area_code,mcc,mnc,dbm,neighbours\n")
        val iso = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", java.util.Locale.US)
        for (f in fixes) {
            sb.append(iso.format(java.util.Date(f.t))).append(',').append(f.t).append(',')
                .append(f.lat).append(',').append(f.lon).append(',').append(f.acc).append(',')
                .append(if (f.alt.isNaN()) "" else f.alt).append(',')
                .append(if (f.speed.isNaN()) "" else f.speed).append(',')
                .append(if (f.bearing.isNaN()) "" else f.bearing).append(',')
                .append(f.kind).append(',').append(f.gen).append(',').append(f.cid).append(',')
                .append(f.area).append(',').append(f.mcc).append(',').append(f.mnc).append(',')
                .append(if (f.dbm == Int.MIN_VALUE) "" else f.dbm).append(',')
                .append(f.neighbours).append('\n')
        }
        return sb.toString()
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace("\"", "&quot;")
}
