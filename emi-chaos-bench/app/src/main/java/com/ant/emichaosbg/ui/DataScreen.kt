package com.ant.emichaosbg.ui

import android.content.Context
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.ant.emichaosbg.Exporter
import com.ant.emichaosbg.MaskerService
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * DATA — what this app is actually holding, and who has been following you.
 *
 * Both halves were already native (TrackerWatch, BleWatcher, TowerLog). This screen answers the
 * question a counter-surveillance tool should be able to answer about itself in one place —
 * "what do you have on me" — rather than leaving it spread across panels.
 */
class DataScreen(ctx: Context) : ScrollView(ctx) {

    private val followVals: List<TextView>
    private val towerVals: List<TextView>
    private val followList: LinearLayout
    private val followTag: TextView
    private val towerTag: TextView
    private val exporter = Exporter(ctx.applicationContext)

    init {
        setBackgroundColor(Nx.BG)
        val root = Nx.column(ctx, 10)
        addView(root)

        // ---- follower detection ----
        val fCard = Nx.card(ctx)
        val (fHead, fT) = Nx.header(ctx, "Follower detection"); followTag = fT
        fCard.addView(fHead)
        val fBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        followVals = Nx.statGrid(ctx, fBody, 3,
            listOf("Identities", "Following", "Scanner", "Sightings", "Windows", "Sessions"))
        fBody.addView(Nx.button(ctx, "Refresh") { refresh() }
            .apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
                .apply { topMargin = Nx.dp(ctx, 8) } })
        followList = Nx.column(ctx)
        fBody.addView(followList)
        fCard.addView(fBody)
        fCard.addView(Nx.body(ctx,
            "Detects a BLE tracker TRAVELLING WITH YOU. A single scan can never answer this: a " +
            "tracker in your bag and one on a shelf you walked past are identical in one sweep. " +
            "They differ over time, so a follow requires BOTH persistence across separate scan " +
            "sessions AND real displacement since first sighting. A beacon reaches tens of " +
            "metres; an identity still with you half a kilometre later moved with you.\n\n" +
            "MAC rotation is handled: trackers rotate their address to defeat blocklists but the " +
            "advertisement payload usually stays constant, so identities are keyed on the " +
            "payload and rotation is itself reported.\n\n" +
            "It scans from the foreground service, so it observes with the screen off and the " +
            "app in your pocket — the only state in which a planted tracker actually gets " +
            "followed for hours. SCANNER above says whether it is genuinely observing: a panel " +
            "reading 'nothing following' while nothing is scanning would be indistinguishable " +
            "from an all-clear.\n\n" +
            "It will name your own things. Your tag, your earbuds, a companion's tracker and a " +
            "tag in a shared car all produce a genuine follow signature, because they genuinely " +
            "are following you. Identify it before assuming the worst."))
        root.addView(fCard)

        // ---- tower / position log ----
        val tCard = Nx.card(ctx)
        val (tHead, tT) = Nx.header(ctx, "Tower & position log"); towerTag = tT
        tCard.addView(tHead)
        val tBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        towerVals = Nx.statGrid(ctx, tBody, 3,
            listOf("Fixes", "Unique cells", "Seen once", "Interval", "Distance", "Accuracy gate"))
        val r1 = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 8) } }
        r1.addView(Nx.button(ctx, "Start/Stop") { toggleTower() }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        r1.addView(Nx.button(ctx, "GPX") { exportTower("gpx") }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        r1.addView(Nx.button(ctx, "KML") { exportTower("kml") }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        r1.addView(Nx.button(ctx, "CSV") { exportTower("csv") }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        tBody.addView(r1)
        tCard.addView(tBody)
        tCard.addView(Nx.body(ctx,
            "Records which cell you were attached to, where, and how strongly, on interval and " +
            "distance triggers with an accuracy gate. It exists because the live cellular checks " +
            "have no memory: a cell that appears once and never again, or an identity logged " +
            "kilometres from where it was first seen, is only visible across time. The second " +
            "case is flagged automatically — a fixed tower cannot be in two places.\n\n" +
            "THIS LOG CONTAINS LOCATION, unavoidably — a position log without positions is " +
            "nothing. That is exactly why it is kept OUT of the encrypted vault, which stays " +
            "location-free. Treat this one as sensitive on its own terms.\n\n" +
            "Nothing is uploaded and there is no server to upload to. Export writes a file to " +
            "Downloads; sharing it further is a separate deliberate step."))
        root.addView(tCard)
    }

    fun refresh() {
        val c = context
        runCatching {
            val w = MaskerService.trackerWatch ?: return@runCatching
            val o = JSONObject(w.stats())
            val cands = o.optJSONArray("candidates")
            var following = 0
            if (cands != null) for (i in 0 until cands.length())
                if (cands.optJSONObject(i)?.optBoolean("following") == true) following++
            followVals[0].text = o.optInt("tracked").toString()
            followVals[1].text = following.toString()
            followVals[5].text = o.optLong("sessions").toString()

            // Scanner truth: an all-clear from a scanner that is not running is not an all-clear.
            val b = MaskerService.bleWatcher
            val bs = b?.let { runCatching { JSONObject(it.status()) }.getOrNull() }
            val observing = bs?.optBoolean("running") == true
            followVals[2].text = when {
                bs == null -> "not started"
                observing -> "observing"
                else -> bs.optString("error", "idle")
            }
            followVals[3].text = bs?.optLong("sightings")?.toString() ?: "—"
            followVals[4].text = bs?.optLong("flushes")?.toString() ?: "—"
            followTag.text = when {
                !observing -> "scanner idle"
                following > 0 -> "$following FOLLOWING"
                else -> "nothing following"
            }

            followList.removeAllViews()
            if (cands != null) {
                val rows = (0 until cands.length()).mapNotNull { cands.optJSONObject(it) }
                    .sortedByDescending { (if (it.optBoolean("following")) 1000 else 0) + it.optInt("sessions") }
                rows.take(12).forEach { x ->
                    val txt = (if (x.optBoolean("following")) "FOLLOWING · " else "") +
                        x.optString("label") + "  ·  " + x.optInt("sessions") + " scans  ·  " +
                        x.optInt("addresses") + " MAC(s)  ·  " + x.optLong("minutes") + " min  ·  moved " +
                        x.optInt("movedM") + "m  ·  " + x.optInt("rssi") + "dBm"
                    followList.addView(
                        Nx.finding(c, if (x.optBoolean("following")) 3 else 1, txt),
                        LinearLayout.LayoutParams(-1, -2).apply { topMargin = Nx.dp(c, 6) })
                }
                if (rows.isEmpty())
                    followList.addView(Nx.body(c, "No device has been seen often enough to assess yet."))
            }
        }
        runCatching {
            val t = MaskerService.ensureTowerLog(c)
            val o = JSONObject(t.stats())
            towerTag.text = if (o.optBoolean("running")) "logging" else "off"
            towerVals[0].text = o.optInt("fixes").toString()
            towerVals[1].text = o.optInt("uniqueCells").toString()
            towerVals[2].text = o.optInt("singletonCells").toString()
            towerVals[3].text = o.optLong("intervalSec").toString() + "s"
            towerVals[4].text = o.optDouble("distanceM", 0.0).toInt().toString() + "m"
            towerVals[5].text = o.optDouble("accuracyGateM", 0.0).toInt().toString() + "m"
        }
    }

    private fun toggleTower() {
        val t = MaskerService.ensureTowerLog(context)
        val now = if (t.isRunning()) { t.stop(); false } else { t.start(); true }
        Toast.makeText(context,
            if (now) "Tower & position logging on — this log contains location"
            else "Tower logging off", Toast.LENGTH_SHORT).show()
        refresh()
    }

    private fun exportTower(kind: String) {
        Thread {
            val t = MaskerService.ensureTowerLog(context)
            val body = when (kind) {
                "gpx" -> t.exportGpx(); "kml" -> t.exportKml(); else -> t.exportCsv()
            }
            val mime = when (kind) {
                "gpx" -> "application/gpx+xml"
                "kml" -> "application/vnd.google-earth.kml+xml"
                else -> "text/csv"
            }
            val name = "emi-towers-" +
                SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) + "." + kind
            // Header/skeleton only means nothing was logged — say so rather than writing a stub.
            val res = if (body.length < 140) null
                else runCatching { JSONObject(exporter.save(name, mime, body)) }.getOrNull()
            post {
                Toast.makeText(context,
                    when {
                        body.length < 140 -> "Nothing logged yet"
                        res?.optBoolean("ok") == true ->
                            "Saved to ${res.optString("path")} (${res.optInt("bytes")} bytes)"
                        else -> "Export failed — ${res?.optString("reason") ?: "unknown"}"
                    }, Toast.LENGTH_LONG).show()
            }
        }.apply { isDaemon = true }.start()
    }
}
