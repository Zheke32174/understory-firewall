package com.ant.emichaosbg.ui

import android.content.Context
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.ant.emichaosbg.Exporter
import com.ant.emichaosbg.MaskerService
import com.ant.emichaosbg.SecureLog
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * AUDIT — the one-screen answer to "how exposed am I, and what is the single worst thing."
 *
 * Every number here is produced by AuditFusion from the detectors that were already running; this
 * screen draws them where the fusion put them, exactly as DataScreen draws follower/tower state.
 * It adds one genuinely new action a counter-surveillance tool should have and did not: a single
 * forensic CASE REPORT — posture plus the evidence vault's own integrity proof — exportable as a
 * self-contained document, with the export itself recorded to the vault as chain of custody.
 *
 * Nothing here scans, transmits, or reaches a radio. It reads, grades, and (on an explicit press)
 * writes a file the user chooses to share.
 */
class AuditScreen(ctx: Context) : ScrollView(ctx) {

    private val postureVals: List<TextView>
    private val evidenceVals: List<TextView>
    private val findingList: LinearLayout
    private val postureTag: TextView
    private val evidenceTag: TextView
    private val exporter = Exporter(ctx.applicationContext)

    init {
        setBackgroundColor(Nx.BG)
        val root = Nx.column(ctx, 10)
        addView(root)

        // ---- posture ----
        val pCard = Nx.card(ctx)
        val (pHead, pT) = Nx.header(ctx, "Security posture"); postureTag = pT
        pCard.addView(pHead)
        val pBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        postureVals = Nx.statGrid(ctx, pBody, 3,
            listOf("Grade", "Score", "Critical", "Elevated", "Watch", "Gaps"))
        pBody.addView(Nx.button(ctx, "Refresh") { refresh() }
            .apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
                .apply { topMargin = Nx.dp(ctx, 8) } })
        findingList = Nx.column(ctx)
        pBody.addView(findingList)
        pCard.addView(pBody)
        pCard.addView(Nx.body(ctx,
            "Folds every detector — cellular, Wi-Fi, LAN/interception, process integrity, follower " +
            "detection and the evidence vault's own integrity — into one graded posture, worst " +
            "finding first. GRADE is driven by the single most severe signal; SCORE is an at-a-" +
            "glance rollup out of 100.\n\n" +
            "A check that could not run is a COVERAGE GAP, counted separately and never as an all-" +
            "clear: 'nothing found' from a detector that never ran is the most dangerous thing this " +
            "app could imply, so it refuses to imply it.\n\n" +
            "Every signal folded in is a heuristic. A high grade means several fired at once — a " +
            "strong reason to look closer, never proof. The detectors run from the background " +
            "service, so this posture keeps updating with the screen off."))
        root.addView(pCard)

        // ---- evidence & export ----
        val eCard = Nx.card(ctx)
        val (eHead, eT) = Nx.header(ctx, "Evidence & chain of custody"); evidenceTag = eT
        eCard.addView(eHead)
        val eBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        evidenceVals = Nx.statGrid(ctx, eBody, 4,
            listOf("Records", "Chain", "HW key", "Masking"))
        val r1 = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 8) } }
        r1.addView(Nx.button(ctx, "Report HTML") { exportReport(true) }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        r1.addView(Nx.button(ctx, "Report JSON") { exportReport(false) }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        eBody.addView(r1)
        val r2 = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 6) } }
        r2.addView(Nx.button(ctx, "Vault JSON") { exportVault("json") }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        r2.addView(Nx.button(ctx, "Vault CSV") { exportVault("csv") }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        eBody.addView(r2)
        eCard.addView(eBody)
        eCard.addView(Nx.body(ctx,
            "The CASE REPORT is one self-contained document — the graded posture plus the encrypted " +
            "vault's own hash-chain verification embedded verbatim, so the file carries its own " +
            "proof of integrity. HTML is the human-readable version; JSON is the machine bundle.\n\n" +
            "Exporting is itself logged to the vault as a chain-of-custody entry — the store can " +
            "answer later whether a copy was taken off the device, when, and how large. Reports are " +
            "location-free and identity-free by construction; positions live only in the tower log " +
            "on the Data screen and are never merged in here.\n\n" +
            "Nothing is uploaded and there is no server to upload to. Export writes a file to " +
            "Downloads; sharing it further is a separate, deliberate step."))
        root.addView(eCard)
    }

    fun refresh() {
        val app = context.applicationContext
        Async.load(this, {
            runCatching { MaskerService.ensureAuditEngine(app).run() }.getOrNull()
        }) { json -> render(json) }
    }

    private fun render(json: String?) {
        val o = json?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return
        if (!o.optBoolean("ok", false)) {
            postureTag.text = "not yet run"
            return
        }
        val counts = o.optJSONObject("counts") ?: JSONObject()
        val grade = o.optString("grade", "clear")
        postureVals[0].text = grade
        postureVals[1].text = o.optInt("score", 0).toString()
        postureVals[2].text = counts.optInt("critical", 0).toString()
        postureVals[3].text = counts.optInt("warning", 0).toString()
        postureVals[4].text = counts.optInt("info", 0).toString()
        postureVals[5].text = counts.optInt("gaps", 0).toString()
        postureTag.text = when (grade) {
            "critical" -> "CRITICAL — act now"
            "elevated" -> "ELEVATED — look closer"
            "watch" -> "WATCH"
            else -> "clear"
        }

        // Findings + gaps, worst first.
        findingList.removeAllViews()
        val top = o.optJSONArray("topFindings")
        if (top != null) for (i in 0 until top.length()) {
            val f = top.optJSONObject(i) ?: continue
            findingList.addView(
                Nx.finding(context, f.optInt("sev", 1),
                    "[" + f.optString("category") + "] " + f.optString("text")),
                LinearLayout.LayoutParams(-1, -2).apply { topMargin = Nx.dp(context, 6) })
        }
        val gaps = o.optJSONArray("coverageGaps")
        if (gaps != null) for (i in 0 until gaps.length()) {
            val g = gaps.optJSONObject(i) ?: continue
            findingList.addView(
                Nx.finding(context, 1, "gap · " + g.optString("title") + " — " + g.optString("why")),
                LinearLayout.LayoutParams(-1, -2).apply { topMargin = Nx.dp(context, 6) })
        }
        if ((top?.length() ?: 0) == 0 && (gaps?.length() ?: 0) == 0)
            findingList.addView(Nx.body(context, "No finding and no coverage gap — every check ran clear."))

        val status = o.optJSONObject("status") ?: JSONObject()
        evidenceVals[0].text = status.optInt("evidenceRecords", 0).toString()
        val intact = status.optBoolean("evidenceChainIntact", false)
        evidenceVals[1].text = if (intact) "verified" else "BROKEN"
        evidenceVals[2].text = if (status.optBoolean("strongBox", false)) "yes" else "no"
        evidenceVals[3].text = if (status.optBoolean("masking", false)) "on" else "off"
        evidenceTag.text = if (intact) "chain verified" else "CHAIN BROKEN"
    }

    private fun exportReport(html: Boolean) {
        val app = context.applicationContext
        Async.load(this, {
            val engine = MaskerService.ensureAuditEngine(app)
            val body = engine.caseReport(html)
            val records = runCatching {
                JSONObject(engine.cached()).optJSONObject("status")?.optInt("evidenceRecords", 0) ?: 0
            }.getOrDefault(0)
            val ext = if (html) "html" else "json"
            val mime = if (html) "text/html" else "application/json"
            val name = "emi-case-" +
                SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) + "." + ext
            val res = runCatching { JSONObject(exporter.save(name, mime, body)) }
                .getOrElse { JSONObject().put("ok", false).put("reason", it.javaClass.simpleName) }
            // Chain of custody: record the export against the vault only once the file is real.
            if (res.optBoolean("ok", false)) {
                runCatching { engine.noteExport("case-$ext", res.optInt("bytes", 0), records) }
            }
            res
        }) { res -> toastExport(res) }
    }

    private fun exportVault(kind: String) {
        val app = context.applicationContext
        Async.load(this, {
            val log = SecureLog(app)                    // Keystore work stays off the main thread
            val body = if (kind == "csv") log.exportCsv() else log.exportJson()
            val mime = if (kind == "csv") "text/csv" else "application/json"
            val records = runCatching { JSONObject(log.verify()).optInt("records", 0) }.getOrDefault(0)
            val name = "emi-vault-" +
                SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) + "." + kind
            val res = runCatching { JSONObject(exporter.save(name, mime, body)) }
                .getOrElse { JSONObject().put("ok", false).put("reason", it.javaClass.simpleName) }
            if (res.optBoolean("ok", false)) {
                runCatching {
                    MaskerService.ensureAuditEngine(app).noteExport("vault-$kind", res.optInt("bytes", 0), records)
                }
            }
            res
        }) { res -> toastExport(res) }
    }

    private fun toastExport(res: JSONObject) {
        Toast.makeText(context,
            if (res.optBoolean("ok", false))
                "Saved to ${res.optString("path")} (${res.optInt("bytes")} bytes)"
            else "Export failed — ${res.optString("reason").ifBlank { "unknown" }}",
            Toast.LENGTH_LONG).show()
    }
}
