package com.ant.emichaosbg

import android.content.Context
import android.webkit.JavascriptInterface
import org.json.JSONObject

/**
 * AUDIT ENGINE — the thin Android layer over AuditFusion.
 *
 * It does three jobs and nothing else:
 *   1. GATHER. Read each service-owned detector's own cached JSON (nobody re-scans here — the
 *      escalation timer has just run them, and re-running would double the binder/file work the
 *      whole app is built to keep off any hot path). Verify the evidence vault's own chain.
 *   2. FUSE. Hand the gathered strings to the pure AuditFusion and cache the graded result.
 *   3. RECORD. When the posture GRADE changes — for better or worse — write one coalesced line to
 *      the same encrypted, hash-chained vault every other detector writes to. A posture history
 *      is then reconstructable from the evidence store itself, with no separate log to protect.
 *
 * WHY A SEPARATE ENGINE AND NOT JUST A UI HELPER. Because the posture is worth having with no UI
 * open at all: the service timer drives run() in the background, so the graded posture and its
 * transitions are logged whether or not anyone is looking — the same reason ScanEngine and the
 * escalation checks are service-owned rather than Activity-owned.
 *
 * CHAIN OF CUSTODY. Exporting evidence off the device is itself a logged event (noteExport). For a
 * forensic/audit tool that is not bookkeeping for its own sake: the vault can now answer "was a
 * copy of this evidence ever taken off the device, when, and how large" from inside the tamper-
 * evident record itself. Nothing about the export is trusted to memory.
 *
 * SAFETY IS INHERITED, NOT RE-ARGUED. This reads JSON the detectors already produced. It starts
 * no scan of its own, touches no radio, and adds no capability — it is a lens over existing
 * observations. The one write it performs is append() to the append-only vault, which is the same
 * write every other detector already performs and the only write the vault has ever supported.
 */
class AuditEngine(private val ctx: Context, private val log: SecureLog) {

    private var lastReport: JSONObject? = null

    // Grade-change logging, coalesced exactly like every other detector so a flapping signal near
    // a boundary cannot spam the vault. A persistent critical is re-affirmed after REAFFIRM_MS so
    // it does not silently age out of the recent view.
    private var lastGrade: String? = null
    private var lastLoggedAt = 0L
    private val COALESCE_MS = 5 * 60_000L
    private val REAFFIRM_MS = 30 * 60_000L

    /**
     * Gather -> fuse -> cache -> (maybe) log. Returns the graded posture JSON.
     *
     * Runs off the main thread (the service timer, or Async.load from the screen). Every read is
     * wrapped so one dead subsystem degrades to a coverage gap rather than taking the audit down —
     * a partial posture is still worth far more than none.
     */
    @Synchronized
    fun run(): String {
        val inputs = HashMap<String, String?>()
        inputs[AuditFusion.IN_CELL] = safe { MaskerService.cellSecurity?.cached() }
        inputs[AuditFusion.IN_WIFI] = safe { MaskerService.scanEngine?.snapshot() }
        inputs[AuditFusion.IN_NET] = safe { MaskerService.netGuard?.cached() }
        inputs[AuditFusion.IN_INTEGRITY] = safe { MaskerService.escalationGuard?.cached() }
        inputs[AuditFusion.IN_TRACKERS] = safe { MaskerService.trackerWatch?.stats() }
        inputs[AuditFusion.IN_EVIDENCE] = safe { log.verify() }
        inputs[AuditFusion.IN_BLE] = safe { MaskerService.bleWatcher?.status() }
        inputs[AuditFusion.IN_MASKING] =
            JSONObject().put("running", MaskerService.isRunning).toString()

        val result = AuditFusion.fuse(inputs, System.currentTimeMillis())
        lastReport = result
        maybeLog(result)
        return result.toString()
    }

    /** The last graded posture without recomputing. Says so honestly when nothing has run yet —
     *  the "never ran is not clean" lesson the rest of the app already absorbed. */
    fun cached(): String =
        (lastReport ?: JSONObject().put("ok", false).put("reason", "not yet run")).toString()

    /**
     * Assemble the full forensic case report (see CaseReport). Gathers the current posture, the
     * vault's own verification, and the app/device metadata into a single self-describing bundle.
     * [html] selects the human-readable report; otherwise the machine bundle.
     */
    fun caseReport(html: Boolean): String {
        val posture = cached().let { if (JSONObject(it).optBoolean("ok", false)) it else this.run() }
        val verify = safe { log.verify() } ?: "{}"
        val meta = JSONObject()
            .put("app", "EMI Chaos Bench")
            .put("appVersion", safe {
                ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName } ?: "?")
            .put("package", ctx.packageName)
            .put("device", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
            .put("sdk", android.os.Build.VERSION.SDK_INT)
        return if (html) CaseReport.buildHtml(posture, verify, meta, System.currentTimeMillis())
        else CaseReport.buildJson(posture, verify, meta, System.currentTimeMillis())
    }

    /**
     * Record that evidence left the device — the chain-of-custody entry. Append-only, like every
     * other write to the vault. Severity 1: it is not an alarm, it is a fact worth being able to
     * prove later. Coalescing is deliberately NOT applied here — every export is its own event.
     */
    fun noteExport(kind: String, bytes: Int, records: Int) {
        val k = kind.take(24)
        try {
            log.append(1, "evidence exported: $k, $bytes bytes, $records record(s) attested",
                "custody", "audit")
        } catch (_: Throwable) {}
    }

    private fun maybeLog(r: JSONObject) {
        val grade = r.optString("grade", "clear")
        val now = System.currentTimeMillis()
        val changed = grade != lastGrade
        val stale = now - lastLoggedAt >= REAFFIRM_MS
        val critical = r.optInt("worstSev", 0) >= 3
        // Log on any grade transition, and re-affirm a standing critical so it stays visible; but
        // never faster than the coalesce window, so a signal flapping across a boundary is quiet.
        if (!changed && !(critical && stale)) return
        if (now - lastLoggedAt < COALESCE_MS && !changed) return

        val c = r.optJSONObject("counts")
        val top = r.optJSONArray("topFindings")?.optJSONObject(0)?.optString("text").orEmpty()
        val sev = r.optInt("worstSev", 0).coerceIn(1, 3)
        val msg = "posture $grade (score ${r.optInt("score", 0)}): " +
            "${c?.optInt("critical", 0) ?: 0} critical / ${c?.optInt("warning", 0) ?: 0} elevated / " +
            "${c?.optInt("gaps", 0) ?: 0} gap" + (if (top.isNotBlank()) " · $top" else "")
        try { log.append(sev, msg.take(400), "posture", "audit") } catch (_: Throwable) {}
        lastGrade = grade
        lastLoggedAt = now
    }

    private inline fun safe(block: () -> String?): String? =
        try { block() } catch (_: Throwable) { null }
}

/**
 * Read-only view onto the audit engine for the WebView page, registered as `EMIAudit`.
 *
 * Same shape as ScanBridge / CellSecurityBridge / NetGuardBridge: the page can ask for the current
 * posture and pull a report, but it has no way to raise, edit, suppress or delete a finding —
 * fusion and recording live on the far side of this boundary. `noteExport` is the single exception
 * and it only APPENDS a custody line; there is deliberately no method here that removes or alters
 * anything, and InvariantsTest pins that.
 */
class AuditBridge(private val engine: AuditEngine) {
    @JavascriptInterface fun run(): String = engine.run()
    @JavascriptInterface fun cached(): String = engine.cached()
    @JavascriptInterface fun reportJson(): String = engine.caseReport(html = false)
    @JavascriptInterface fun reportHtml(): String = engine.caseReport(html = true)
    @JavascriptInterface fun noteExport(kind: String?, bytes: Int, records: Int) =
        engine.noteExport(kind ?: "unknown", bytes, records)
}
