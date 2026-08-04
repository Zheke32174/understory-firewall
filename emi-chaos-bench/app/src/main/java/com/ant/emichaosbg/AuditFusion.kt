package com.ant.emichaosbg

import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.max

/**
 * POSTURE FUSION — the one thing the app could not answer about itself in a single place.
 *
 * Until now every detector reported on its own panel: cellular here, Wi-Fi there, injection
 * detection somewhere else, the evidence vault's own integrity elsewhere again. A person using a
 * counter-surveillance tool in a moment that matters does not want to read six panels and do the
 * arithmetic in their head — they want one honest answer to "how exposed am I right now, and what
 * is the single worst thing." This produces exactly that, and nothing more: it invents no new
 * detector and touches no radio. It reads the JSON the existing subsystems already emit and folds
 * it into one graded posture.
 *
 * IT IS PURE ON PURPOSE. This object has no Android dependency — it takes a map of subsystem-name
 * to that subsystem's own JSON string and returns a JSONObject. That is what makes the fusion
 * unit-testable on a plain JVM (see AuditFusionTest), the same discipline TrackerWatch uses with
 * its injected sink. AuditEngine is the thin Android wrapper that gathers the inputs and logs the
 * result; the judgement lives here where it can be tested against fabricated inputs.
 *
 * EVERY SIGNAL IT FOLDS IN IS STILL A HEURISTIC. This does not upgrade a pile of "go look closer"
 * flags into a verdict. A high posture grade means several heuristics fired at once, which is a
 * stronger reason to look — never proof. The wording downstream keeps saying so.
 *
 * SEVERITY IS THE EXISTING 1..3 SCALE, unchanged: 3 critical, 2 elevated, 1 watch, 0 clear. A
 * check that could not run at all is a COVERAGE GAP, tracked separately, because "nothing found"
 * from a detector that never ran is the most dangerous thing this app can imply — the same lesson
 * EscalationGuard.cached() and BleWatcher.status() already learned the hard way.
 */
object AuditFusion {

    const val FORMAT = "emi-chaos-bench/posture/1"

    /** Points deducted from a starting 100 per category, by severity, plus the coverage-gap cost. */
    private const val PEN_CRIT = 34
    private const val PEN_WARN = 12
    private const val PEN_INFO = 3
    private const val PEN_GAP = 5

    /** Keys of the input map. Kept as constants so the engine and the tests cannot drift apart. */
    const val IN_CELL = "cell"
    const val IN_WIFI = "wifi"
    const val IN_NET = "net"
    const val IN_INTEGRITY = "integrity"
    const val IN_TRACKERS = "trackers"
    const val IN_EVIDENCE = "evidence"
    const val IN_MASKING = "masking"
    const val IN_BLE = "ble"

    private fun parse(inputs: Map<String, String?>, key: String): JSONObject? =
        inputs[key]?.let { runCatching { JSONObject(it) }.getOrNull() }

    /**
     * Fold every subsystem's JSON into one graded posture.
     *
     * @param inputs subsystem-name -> that subsystem's own JSON string (any may be null/absent)
     * @param nowMs  the timestamp to stamp, injected so the result is deterministic under test
     */
    fun fuse(inputs: Map<String, String?>, nowMs: Long): JSONObject {
        val categories = JSONArray()
        val gaps = JSONArray()
        // Collected then sorted by severity so the caller always sees the worst first.
        val findings = ArrayList<JSONObject>()

        var crit = 0; var warn = 0; var info = 0; var gapN = 0; var clean = 0
        var worst = 0
        var score = 100

        // One place every category funnels through, so the counters, the score and the gap list
        // can never disagree with what the category row says.
        fun cat(key: String, title: String, sev: Int, ran: Boolean, status: String, detail: String) {
            categories.put(
                JSONObject().put("key", key).put("title", title)
                    .put("sev", if (ran) sev else 0).put("ran", ran)
                    .put("status", status).put("detail", detail)
            )
            if (!ran) {
                gapN++
                score -= PEN_GAP
                gaps.put(JSONObject().put("category", key).put("title", title).put("why", status))
                return
            }
            worst = max(worst, sev)
            when (sev) {
                3 -> { crit++; score -= PEN_CRIT }
                2 -> { warn++; score -= PEN_WARN }
                1 -> { info++; score -= PEN_INFO }
                else -> clean++
            }
            if (sev >= 1) {
                findings.add(
                    JSONObject().put("sev", sev).put("category", key)
                        .put("text", if (detail.isBlank()) status else "$status — $detail")
                )
            }
        }

        // ---- Cellular posture (CellSecurity) --------------------------------------------------
        run {
            val c = parse(inputs, IN_CELL)
            if (c == null || !c.optBoolean("ok", false)) {
                cat("cell", "Cellular", 0, false,
                    c?.optString("reason").orBlank("not yet run"), "")
            } else {
                val sec = c.optString("security", "unknown")
                val sev = when (sec) { "insecure" -> 3; "weak" -> 2; else -> 0 }
                val note = c.optString("securityNote").orBlank(
                    when (sec) { "ok" -> "posture ok"; "unknown" -> "insufficient data"; else -> sec })
                cat("cell", "Cellular", sev, true, "$sec — $note",
                    "carrier ${c.optString("carrier").orBlank("?")}, ${c.optString("gen").orBlank("?")}")
            }
        }

        // ---- Wi-Fi rogue-AP heuristics (ScanEngine) -------------------------------------------
        run {
            val w = parse(inputs, IN_WIFI)
            when {
                w == null -> cat("wifi", "Wi-Fi", 0, false, "not yet run", "")
                !w.optBoolean("running", false) ->
                    cat("wifi", "Wi-Fi", 0, false,
                        w.optString("why").orBlank("scanner not running"), "")
                else -> {
                    val f = w.optLong("findings", 0L)
                    val sev = if (f > 0L) 2 else 0
                    val loc = w.optBoolean("locationEnabled", true)
                    val detail = "${w.optLong("wifiScans", 0L)} scans, ${w.optInt("networks", 0)} networks" +
                        (if (!loc) " · location off (results limited)" else "")
                    cat("wifi", "Wi-Fi", sev, true,
                        if (f > 0L) "$f heuristic flag(s) raised" else "no rogue-AP heuristic fired", detail)
                }
            }
        }

        // ---- LAN / interception surface (NetGuard) --------------------------------------------
        run {
            val n = parse(inputs, IN_NET)
            if (n == null) {
                cat("net", "Network", 0, false, "not yet run", "")
            } else if (!n.optBoolean("ok", true)) {
                // cached() before the first scan returns {ok:false, reason:...}; a real scan()
                // result carries no "ok" key at all, so the default here keeps it in the findings
                // path rather than mislabelling a completed scan as a gap.
                cat("net", "Network", 0, false, n.optString("reason").orBlank("not yet run"), "")
            } else {
                val dupes = n.optJSONArray("duplicateMacs")?.length() ?: 0
                val proxy = n.optString("httpProxy")
                val portal = n.optBoolean("captivePortal", false)
                val sev = when {
                    proxy.isNotBlank() -> 3
                    dupes > 0 -> 3
                    portal -> 1
                    else -> 0
                }
                val status = when {
                    proxy.isNotBlank() -> "HTTP proxy set on this network"
                    dupes > 0 -> "$dupes host(s) share a MAC (possible ARP impersonation)"
                    portal -> "captive portal present"
                    else -> "no interception heuristic fired"
                }
                val vpn = if (n.optBoolean("vpn", false)) "vpn up" else "no vpn"
                cat("net", "Network", sev, true, status,
                    "$vpn · dns ${n.optString("dnsEncrypted").orBlank("?")}")
            }
        }

        // ---- Process integrity / injection (EscalationGuard) ----------------------------------
        run {
            val e = parse(inputs, IN_INTEGRITY)
            if (e == null || !e.optBoolean("ran", false)) {
                cat("integrity", "Integrity", 0, false,
                    e?.optString("note").orBlank("not yet run"), "")
            } else if (e.optBoolean("clean", true)) {
                cat("integrity", "Integrity", 0, true, "clean — no injection heuristic fired",
                    "${e.optInt("mapCount", 0)} maps scanned")
            } else {
                val fs = e.optJSONArray("findings")
                var mx = 1
                var top = ""
                if (fs != null) for (i in 0 until fs.length()) {
                    val fo = fs.optJSONObject(i) ?: continue
                    val s = fo.optInt("sev", 1)
                    if (s >= mx) { mx = s; top = fo.optString("what").orBlank(fo.optString("key")) }
                }
                cat("integrity", "Integrity", mx, true,
                    "${e.optInt("count", 0)} finding(s)", top.take(160))
            }
        }

        // ---- Follower detection (TrackerWatch) ------------------------------------------------
        run {
            val t = parse(inputs, IN_TRACKERS)
            if (t == null) {
                cat("trackers", "Followers", 0, false, "not yet run", "")
            } else {
                val cands = t.optJSONArray("candidates")
                var following = 0
                var topLabel = ""
                if (cands != null) for (i in 0 until cands.length()) {
                    val co = cands.optJSONObject(i) ?: continue
                    if (co.optBoolean("following", false)) {
                        following++
                        if (topLabel.isEmpty()) topLabel = co.optString("label").orBlank("device")
                    }
                }
                val sev = if (following > 0) 3 else 0
                cat("trackers", "Followers", sev, true,
                    if (following > 0) "$following device(s) travelling with you" else "nothing following",
                    "${t.optInt("tracked", 0)} identities tracked" +
                        (if (topLabel.isNotEmpty()) " · e.g. $topLabel" else ""))
            }
        }

        // ---- Evidence-store integrity (SecureLog.verify) --------------------------------------
        // The vault is tamper-EVIDENT: if its own hash chain no longer verifies, that is itself a
        // high-severity finding, because it means the evidence a person is relying on has been
        // altered or truncated underneath them.
        var evRecords = 0
        var chainIntact = true
        var strongBox = false
        run {
            val v = parse(inputs, IN_EVIDENCE)
            if (v == null) {
                cat("evidence", "Evidence store", 0, false, "not yet verified", "")
            } else {
                chainIntact = v.optBoolean("chainIntact", false) && v.optBoolean("headMatches", false)
                evRecords = v.optInt("records", v.optInt("headCount", 0))
                strongBox = v.optBoolean("strongBox", false)
                val sev = if (chainIntact) 0 else 3
                cat("evidence", "Evidence store", sev, true,
                    if (chainIntact) "chain verified, $evRecords record(s)"
                    else "CHAIN BROKEN — ${v.optString("likelyCause").orBlank("integrity failure")}",
                    "hardware-backed key: ${if (strongBox) "yes" else "no"}")
            }
        }

        // ---- Masking (the disruption layer) status --------------------------------------------
        val masking = parse(inputs, IN_MASKING)?.optBoolean("running", false) ?: false
        val bleRunning = parse(inputs, IN_BLE)?.optBoolean("running", false) ?: false

        findings.sortWith(compareByDescending<JSONObject> { it.optInt("sev") }
            .thenBy { it.optString("category") })
        val top = JSONArray()
        findings.take(8).forEach { top.put(it) }

        val grade = when (worst) { 3 -> "critical"; 2 -> "elevated"; 1 -> "watch"; else -> "clear" }

        return JSONObject()
            .put("ok", true)
            .put("format", FORMAT)
            .put("at", nowMs)
            .put("score", score.coerceIn(0, 100))
            .put("grade", grade)
            .put("worstSev", worst)
            .put("counts", JSONObject()
                .put("critical", crit).put("warning", warn).put("info", info)
                .put("gaps", gapN).put("clean", clean))
            .put("categories", categories)
            .put("topFindings", top)
            .put("coverageGaps", gaps)
            .put("status", JSONObject()
                .put("masking", masking)
                .put("bleObserving", bleRunning)
                .put("strongBox", strongBox)
                .put("evidenceRecords", evRecords)
                .put("evidenceChainIntact", chainIntact))
    }

    /** org.json returns "" for a missing optString and the caller usually wants a real default;
     *  and optString(key) on a null receiver would NPE, so this centralises "" -> fallback. */
    private fun String?.orBlank(fallback: String): String =
        if (this.isNullOrBlank()) fallback else this
}
