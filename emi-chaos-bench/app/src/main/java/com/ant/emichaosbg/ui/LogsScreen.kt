package com.ant.emichaosbg.ui

import android.content.Context
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.ant.emichaosbg.Exporter
import com.ant.emichaosbg.SecureLog
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * LOGS — the evidence, rendered where it is stored.
 *
 * The vault was always native; the page was reading records back across a bridge, decrypting
 * them on the way, and drawing them. That round trip is what caused the freeze earlier in this
 * project: verify() walks and decrypts the whole log, and the display loop was calling it once
 * a second on the UI thread. Rendering natively does not just remove a formatting layer, it
 * removes the incentive to poll an expensive call from a render loop at all.
 *
 * The same discipline still applies here, and the reported freeze on pressing LOGS proved it
 * had been applied by care rather than by structure — care that then missed two paths:
 *
 *   1. count() was documented as cheap but walked and DECRYPTED the entire log to increment a
 *      counter. It now reads the sealed head, which already stores the count. O(1).
 *   2. The screen still touched the vault on the main thread, because `val log = SecureLog(...)`
 *      runs during construction — inside the tab's click handler — and first use generates the
 *      Keystore key.
 *
 * So the rule is now structural: NOTHING on this screen touches SecureLog on the main thread.
 * The field is lazy, and every dereference is inside Async. count() is cheap AND off-thread;
 * read(), verify() and the exports are O(records) with a decrypt each and additionally require
 * an explicit press.
 */
class LogsScreen(ctx: Context) : ScrollView(ctx) {

    private val vaultVals: List<TextView>
    private val entries: LinearLayout
    private val tag: TextView
    private lateinit var lastExport: TextView
    // LAZY, AND DEREFERENCED ONLY FROM A BACKGROUND THREAD.
    //
    // As a `val` this constructed SecureLog during LogsScreen's own construction — which
    // happens on the main thread, inside the Logs tab's click handler. SecureLog's constructor
    // mkdirs(), and its first real use generates a non-exportable AES key in the Keystore;
    // StrongBox key generation on a secure element is not fast. That is the freeze that was
    // reported on pressing Logs, and it is invisible in a debug build on a warm Keystore.
    //
    // `by lazy` moves the cost to first dereference, and every dereference below is inside an
    // Async block, so the cost lands on the data thread instead of the frame deadline.
    private val log by lazy { SecureLog(ctx.applicationContext) }
    private val exporter by lazy { Exporter(ctx.applicationContext) }
    private val fmt = SimpleDateFormat("MMM d HH:mm:ss", Locale.US)

    init {
        setBackgroundColor(Nx.BG)
        val root = Nx.column(ctx, 10)
        addView(root)

        val card = Nx.card(ctx)
        val (head, t) = Nx.header(ctx, "Encrypted vault"); tag = t
        card.addView(head)
        val body = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        vaultVals = Nx.statGrid(ctx, body, 3, listOf("Records", "Chain", "Newest"))

        val r1 = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 8) } }
        r1.addView(Nx.button(ctx, "Load") { loadEntries() }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        r1.addView(Nx.button(ctx, "Verify") { verify() }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        body.addView(r1)

        val r2 = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 6) } }
        r2.addView(Nx.button(ctx, "Export JSON") { export(json = true) }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        r2.addView(Nx.button(ctx, "Export CSV") { export(json = false) }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        body.addView(r2)

        // SHARE — because "it saved to Downloads" is only useful if the file can then be found.
        // This hands the same content straight to the system share sheet, so the log can be sent
        // somewhere without locating a file at all. Reported as an export that produced nothing
        // findable; a share sheet fails visibly rather than silently.
        val r3 = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 6) } }
        r3.addView(Nx.button(ctx, "Share JSON") { share(json = true) }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        r3.addView(Nx.button(ctx, "Share CSV") { share(json = false) }
            .apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { leftMargin = Nx.dp(ctx, 6) } })
        body.addView(r3)

        // Where the last export actually landed, kept on screen. A toast is gone in three
        // seconds and cannot be re-read; this is the answer to "where did it go".
        lastExport = Nx.body(ctx, "No export yet this session.")
        body.addView(lastExport)

        entries = Nx.column(ctx)
        body.addView(entries)
        card.addView(body)
        card.addView(Nx.body(ctx,
            "The durable record. Encrypted with a non-exportable Keystore key, append-only, and " +
            "hash-chained so a removed or edited entry is detectable rather than silent. There " +
            "is no delete or clear anywhere on this interface — not hidden, not gated, absent.\n\n" +
            "Every entry carries the device context at the moment it was recorded: battery and " +
            "charge state, temperature, screen on/dozing, network TYPE, whether the masker was " +
            "running, uptime and device. That is what turns a timestamp into something you can " +
            "reason from — was the phone idle and face-down or in use, was this a live " +
            "observation or the idle baseline. Context is sealed inside the same record as the " +
            "message, so the same authentication tag and hash chain cover it.\n\n" +
            "It carries NO location, SSID, BSSID, cell identity or serial. This is the file most " +
            "worth stealing; a precise movement history would be the most damaging thing in it.\n\n" +
            "Load and Verify are deliberate presses, not a refresh loop: both decrypt every " +
            "record, and polling that from a render loop is what froze this app earlier. They " +
            "run off the main thread."))
        root.addView(card)
        refreshCheap()
    }

    /**
     * Cheap in complexity — count() is now O(1) against the sealed head — but still NOT free:
     * it decrypts that head, and the first call of the session may generate the Keystore key.
     * So it goes through Async like everything else here. "Cheap" was the assumption that put
     * this call on the main thread in the first place.
     */
    fun refreshCheap() {
        tag.text = "reading…"
        Async.load(this, {
            // Cheap health check alongside the count. The count alone was actively misleading
            // on a real device: the head reported 830 records while only 279 could be read, and
            // this screen displayed the head's number with no indication that the rest were
            // unreachable. A vault that cannot be read is the one state the user must not have
            // to go hunting through an export to discover.
            val n = log.count()
            val readable = log.readableCount()
            longArrayOf(n, readable)
        }) { r ->
            val n = r[0]; val readable = r[1]
            vaultVals[0].text = n.toString()
            tag.text = when {
                n == 0L -> "empty"
                readable < n -> "UNREADABLE PAST #$readable"
                else -> "$n record(s)"
            }
            if (readable < n) {
                vaultVals[1].text = "BROKEN"
                lastExport.text = "⚠ THE VAULT IS NOT FULLY READABLE.\n\n" +
                    "The head counts $n records; only $readable can be decrypted. The remaining " +
                    "${n - readable} are still on disk but cannot be authenticated, so they " +
                    "cannot be shown or exported.\n\n" +
                    "Press VERIFY for the diagnosis — it distinguishes a sequence slip caused " +
                    "by this app from data that authenticates under no sequence at all, which " +
                    "would mean something else wrote to the file."
            }
        }
    }

    private fun bg(work: () -> Unit) = Async.run(work)

    private fun loadEntries() {
        tag.text = "loading…"
        bg {
            val raw = log.read(80)
            val arr = runCatching { JSONArray(raw) }.getOrElse { JSONArray() }
            post {
                entries.removeAllViews()
                if (arr.length() == 0) {
                    entries.addView(Nx.body(context, "No findings recorded yet."))
                } else {
                    for (i in 0 until arr.length()) {
                        val o = arr.optJSONObject(i) ?: continue
                        entries.addView(row(o), LinearLayout.LayoutParams(-1, -2)
                            .apply { topMargin = Nx.dp(context, 6) })
                    }
                    vaultVals[2].text = fmt.format(Date(arr.optJSONObject(0)?.optLong("t") ?: 0L))
                }
                refreshCheap()
            }
        }
    }

    private fun row(o: JSONObject): TextView {
        val ctxJson = o.optJSONObject("ctx")
        val bits = ArrayList<String>()
        ctxJson?.let { c ->
            c.optInt("battery", -1).let { if (it >= 0) bits.add("$it%") }
            if (c.has("charging")) bits.add(if (c.optBoolean("charging")) "charging" else "battery")
            if (c.has("screenOn")) bits.add(if (c.optBoolean("screenOn")) "screen on" else "screen off")
            c.optString("net", "").let { if (it.isNotBlank()) bits.add(it) }
            if (c.optBoolean("masking")) bits.add("masking")
        }
        val ctxLine = if (bits.isEmpty()) "" else "\n" + bits.joinToString(" · ")
        val text = "#${o.optLong("seq")}  ${fmt.format(Date(o.optLong("t")))}  " +
            "[${o.optString("badge", "-")}]  ${o.optString("src", "")}\n" +
            o.optString("msg") + ctxLine
        return Nx.finding(context, o.optInt("sev", 1), text)
    }

    private fun verify() {
        tag.text = "verifying…"
        bg {
            val v = runCatching { JSONObject(log.verify()) }.getOrNull()
            post {
                val ok = v?.optBoolean("ok") == true
                vaultVals[1].text = if (ok) "intact" else "BROKEN"
                tag.text = if (ok) "chain intact" else "CHAIN BROKEN"
                Toast.makeText(context,
                    if (ok) "Chain verified — every record authenticates and links to its predecessor"
                    else "Chain verification FAILED" + (v?.optString("reason")?.let { ": $it" } ?: ""),
                    Toast.LENGTH_LONG).show()
                refreshCheap()
            }
        }
    }

    private fun name(json: Boolean) =
        "emi-vault-" + SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) +
            if (json) ".json" else ".csv"

    private fun mime(json: Boolean) = if (json) "application/json" else "text/csv"

    private fun export(json: Boolean) {
        Async.load(this, {
            val body = if (json) log.exportJson() else log.exportCsv()
            runCatching { JSONObject(exporter.save(name(json), mime(json), body))
                .put("chars", body.length) }
                .getOrElse { JSONObject().put("ok", false).put("reason", it.javaClass.simpleName) }
        }) { res ->
            val ok = res.optBoolean("ok")
            val msg = if (ok)
                "Saved to ${res.optString("path")} (${res.optInt("bytes")} bytes)" +
                    if (res.optBoolean("fallback")) " — app-private fallback, reachable over USB" else ""
            else "Export FAILED — ${res.optString("reason").ifBlank { "unknown" }}"
            // Persisted on screen, not just toasted: the report was "there are no logs at that
            // location", and a toast that has already vanished cannot be checked against the
            // folder being looked in.
            lastExport.text = msg + "\n\nInternal storage > Download. If it is not there, use " +
                "Share instead — that hands the file to another app directly and does not " +
                "depend on finding it in a folder."
            Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
        }
    }

    private fun share(json: Boolean) {
        Async.load(this, {
            val body = if (json) log.exportJson() else log.exportCsv()
            runCatching { JSONObject(exporter.share(name(json), mime(json), body)) }
                .getOrElse { JSONObject().put("ok", false).put("reason", it.javaClass.simpleName) }
        }) { res ->
            if (!res.optBoolean("ok")) {
                val why = res.optString("reason").ifBlank { "unknown" }
                lastExport.text = "Share FAILED — $why"
                Toast.makeText(context, "Share failed — $why", Toast.LENGTH_LONG).show()
            } else {
                lastExport.text = "Shared ${res.optString("path")} — pick a destination in the " +
                    "sheet. Nothing left the device until you choose one."
            }
        }
    }
}
