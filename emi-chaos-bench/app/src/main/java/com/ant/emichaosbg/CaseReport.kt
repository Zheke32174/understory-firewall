package com.ant.emichaosbg

import org.json.JSONArray
import org.json.JSONObject

/**
 * CASE REPORT — a single self-describing evidence bundle for getting a posture off the device.
 *
 * The vault already exports its raw records (SecureLog.exportJson/exportCsv) and the tower log
 * already exports positions (GPX/KML/CSV). What was missing is the thing a person actually hands
 * to someone else — a lawyer, a journalist's security desk, a threat-model reviewer: one document
 * that says, at a moment in time, what the tool observed, how exposed it judged the device to be,
 * AND whether the evidence store backing that judgement still verifies against its own hash chain.
 *
 * TWO FORMATS, SAME CONTENT.
 *   - buildJson  — the machine bundle: posture + the vault's verify() result + metadata, under a
 *     versioned `format` string, following exactly the convention SecureLog.exportJson set
 *     (a `format` tag and an EMBEDDED verification block, so the file carries its own proof).
 *   - buildHtml  — the human report: the same data laid out to be read, fully self-contained (no
 *     remote fonts, scripts or styles — a forensic document must render identically offline and
 *     cannot be allowed to phone home).
 *
 * IT EMBEDS verify(), IT DOES NOT RE-IMPLEMENT IT. The integrity claim in the report is SecureLog's
 * own chain verification, copied in verbatim. There is exactly one integrity checker in this app
 * and this is not a second one.
 *
 * REDACTION IS PRESERVED. The report carries what the vault carries, and the vault is location-free
 * and identity-free by construction (see LogContext). Positions live only in the tower log and are
 * deliberately NOT pulled in here — a case report is safe to share in a way a position log is not,
 * and merging them would quietly destroy that property. The report states this in-band so a reader
 * knows what it does and does not contain.
 *
 * PURE ON PURPOSE, like AuditFusion: strings in, strings out, no Android — so CaseReportTest can
 * assert the structure and the embedded-verification invariant on a plain JVM.
 */
object CaseReport {

    const val FORMAT = "emi-chaos-bench/case-report/1"

    private const val REDACTION =
        "This report is location-free and identity-free by construction: it carries the encrypted " +
        "vault's findings and its integrity proof, never GPS positions, SSIDs, cell identities or " +
        "account data. Position history lives only in the separate tower log and is not included."

    fun buildJson(postureJson: String, verifyJson: String, meta: JSONObject, nowMs: Long): String {
        val posture = runCatching { JSONObject(postureJson) }.getOrDefault(JSONObject())
        val verify = runCatching { JSONObject(verifyJson) }.getOrDefault(JSONObject())
        return JSONObject()
            .put("format", FORMAT)
            .put("generatedAt", nowMs)
            .put("meta", meta)
            .put("posture", posture)
            .put("integrity", verify)   // the vault's OWN verify() — the chain-of-custody proof
            .put("redaction", REDACTION)
            .toString(2)
    }

    fun buildHtml(postureJson: String, verifyJson: String, meta: JSONObject, nowMs: Long): String {
        val p = runCatching { JSONObject(postureJson) }.getOrDefault(JSONObject())
        val v = runCatching { JSONObject(verifyJson) }.getOrDefault(JSONObject())

        val grade = p.optString("grade", "unknown")
        val score = p.optInt("score", -1)
        val counts = p.optJSONObject("counts") ?: JSONObject()
        val gradeColor = when (grade) {
            "critical" -> "#c0392b"; "elevated" -> "#d68910"; "watch" -> "#b7950b"; else -> "#2c6f68"
        }

        val sb = StringBuilder()
        sb.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
        sb.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        sb.append("<title>EMI Chaos Bench — Case Report</title><style>")
        sb.append(
            "body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#cfcabc;color:#23201b;" +
            "margin:0;padding:24px;line-height:1.5}main{max-width:820px;margin:0 auto}" +
            "h1{font-size:20px;letter-spacing:.06em;margin:0 0 4px}h2{font-size:13px;letter-spacing:.08em;" +
            "text-transform:uppercase;border-bottom:1px solid #a9a290;padding-bottom:6px;margin:28px 0 12px}" +
            ".sub{color:#5c5749;font-size:12px;margin:0 0 20px}" +
            ".grade{display:inline-block;padding:10px 16px;border-radius:4px;color:#fff;font-weight:bold;" +
            "letter-spacing:.1em;text-transform:uppercase}.score{font-size:34px;font-weight:bold;margin-left:14px}" +
            "table{width:100%;border-collapse:collapse;font-size:12px;margin:6px 0}" +
            "td,th{text-align:left;padding:7px 8px;border-bottom:1px solid #d5d0c1;vertical-align:top}" +
            "th{color:#5c5749;font-weight:normal;text-transform:uppercase;font-size:10px;letter-spacing:.06em}" +
            ".sev3{border-left:4px solid #c0392b}.sev2{border-left:4px solid #d68910}" +
            ".sev1{border-left:4px solid #a9a290}.sev0{border-left:4px solid #2c6f68}" +
            ".note{background:#dcd7c9;padding:12px 14px;font-size:11.5px;color:#5c5749;margin:10px 0}" +
            ".ok{color:#2c6f68;font-weight:bold}.bad{color:#c0392b;font-weight:bold}" +
            "pre{background:#e6e1d4;padding:12px;overflow-x:auto;font-size:11px}")
        sb.append("</style></head><body><main>")

        sb.append("<h1>EMI Chaos Bench — Case Report</h1>")
        sb.append("<p class=\"sub\">").append(esc(meta.optString("app"))).append(" ")
            .append(esc(meta.optString("appVersion"))).append(" · ")
            .append(esc(meta.optString("device"))).append(" · SDK ")
            .append(meta.optInt("sdk", 0)).append(" · generated ").append(nowMs).append("</p>")

        // Headline grade + score
        sb.append("<p><span class=\"grade\" style=\"background:").append(gradeColor).append("\">")
            .append(esc(grade)).append("</span>")
        if (score >= 0) sb.append("<span class=\"score\" style=\"color:").append(gradeColor)
            .append("\">").append(score).append("<span style=\"font-size:14px;color:#5c5749\">/100</span></span>")
        sb.append("</p>")
        sb.append("<p class=\"sub\">")
            .append(counts.optInt("critical", 0)).append(" critical · ")
            .append(counts.optInt("warning", 0)).append(" elevated · ")
            .append(counts.optInt("info", 0)).append(" watch · ")
            .append(counts.optInt("gaps", 0)).append(" coverage gap(s)</p>")

        // Category table
        sb.append("<h2>Subsystem posture</h2><table><tr><th>Subsystem</th><th>State</th><th>Detail</th></tr>")
        val cats = p.optJSONArray("categories") ?: JSONArray()
        for (i in 0 until cats.length()) {
            val c = cats.optJSONObject(i) ?: continue
            val ran = c.optBoolean("ran", false)
            val sev = if (!ran) -1 else c.optInt("sev", 0)
            val cls = if (!ran) "sev1" else "sev${sev.coerceIn(0, 3)}"
            sb.append("<tr class=\"").append(cls).append("\"><td>").append(esc(c.optString("title")))
                .append("</td><td>").append(if (!ran) "<span style=\"color:#b7950b\">not run</span>" else esc(c.optString("status")))
                .append("</td><td>").append(esc(c.optString("detail"))).append("</td></tr>")
        }
        sb.append("</table>")

        // Top findings
        val top = p.optJSONArray("topFindings") ?: JSONArray()
        if (top.length() > 0) {
            sb.append("<h2>Prioritised findings</h2><table><tr><th>Sev</th><th>Area</th><th>Finding</th></tr>")
            for (i in 0 until top.length()) {
                val f = top.optJSONObject(i) ?: continue
                val sev = f.optInt("sev", 1)
                sb.append("<tr class=\"sev").append(sev.coerceIn(0, 3)).append("\"><td>")
                    .append(when (sev) { 3 -> "CRIT"; 2 -> "ELEV"; else -> "WATCH" })
                    .append("</td><td>").append(esc(f.optString("category")))
                    .append("</td><td>").append(esc(f.optString("text"))).append("</td></tr>")
            }
            sb.append("</table>")
        }

        // Coverage gaps
        val gaps = p.optJSONArray("coverageGaps") ?: JSONArray()
        if (gaps.length() > 0) {
            sb.append("<h2>Coverage gaps</h2><p class=\"sub\">Checks that could not run. An all-clear " +
                "from a check that never ran is not an all-clear.</p><table><tr><th>Subsystem</th><th>Why</th></tr>")
            for (i in 0 until gaps.length()) {
                val g = gaps.optJSONObject(i) ?: continue
                sb.append("<tr><td>").append(esc(g.optString("title")))
                    .append("</td><td>").append(esc(g.optString("why"))).append("</td></tr>")
            }
            sb.append("</table>")
        }

        // Evidence integrity — the embedded verify()
        val intact = v.optBoolean("chainIntact", false) && v.optBoolean("headMatches", false)
        sb.append("<h2>Evidence integrity (chain of custody)</h2>")
        sb.append("<p>Vault hash chain: ")
            .append(if (intact) "<span class=\"ok\">VERIFIED</span>" else "<span class=\"bad\">BROKEN</span>")
            .append(" · ").append(v.optInt("records", v.optInt("headCount", 0))).append(" record(s)")
            .append(" · hardware-backed key: ").append(if (v.optBoolean("strongBox", false)) "yes" else "no")
            .append("</p>")
        if (!intact) sb.append("<p class=\"bad\">Likely cause: ")
            .append(esc(v.optString("likelyCause").ifBlank { "integrity failure" })).append("</p>")
        sb.append("<p class=\"sub\">The block below is the evidence store's own verification output, " +
            "embedded verbatim so this report carries its own proof.</p>")
        sb.append("<pre>").append(esc(v.toString(2))).append("</pre>")

        sb.append("<div class=\"note\">").append(esc(REDACTION)).append("</div>")
        sb.append("<p class=\"sub\">Every signal here is a heuristic, not a certified detector. A " +
            "high grade is a strong reason to look closer — never proof.</p>")
        sb.append("</main></body></html>")
        return sb.toString()
    }

    /** HTML-escape. Findings quote scanned SSIDs, package labels and /proc paths — all
     *  attacker-influenceable — so nothing reaches the document unescaped. */
    private fun esc(s: String?): String {
        if (s.isNullOrEmpty()) return ""
        val out = StringBuilder(s.length + 16)
        for (ch in s) when (ch) {
            '&' -> out.append("&amp;")
            '<' -> out.append("&lt;")
            '>' -> out.append("&gt;")
            '"' -> out.append("&quot;")
            '\'' -> out.append("&#39;")
            else -> out.append(ch)
        }
        return out.toString()
    }
}
