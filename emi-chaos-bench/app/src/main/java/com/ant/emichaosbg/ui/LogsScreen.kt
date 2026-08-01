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
 * The same discipline still applies here and is enforced by structure rather than by care:
 * count() is cheap and may be read on entry; read() and verify() are O(records) with a decrypt
 * each and run ONLY on an explicit press, on a background thread, never on the main thread.
 */
class LogsScreen(ctx: Context) : ScrollView(ctx) {

    private val vaultVals: List<TextView>
    private val entries: LinearLayout
    private val tag: TextView
    private val log = SecureLog(ctx.applicationContext)
    private val exporter = Exporter(ctx.applicationContext)
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

    /** Safe on entry: a single head-file read, no decryption. */
    fun refreshCheap() {
        runCatching {
            val n = log.count()
            vaultVals[0].text = n.toString()
            tag.text = if (n == 0L) "empty" else "$n record(s)"
        }
    }

    private fun bg(work: () -> Unit) = Thread { runCatching(work) }.apply { isDaemon = true }.start()

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

    private fun export(json: Boolean) {
        bg {
            val body = if (json) log.exportJson() else log.exportCsv()
            val name = "emi-vault-" + SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) +
                if (json) ".json" else ".csv"
            val res = runCatching {
                JSONObject(exporter.save(name, if (json) "application/json" else "text/csv", body))
            }.getOrNull()
            post {
                Toast.makeText(context,
                    if (res?.optBoolean("ok") == true)
                        "Saved to ${res.optString("path")} (${res.optInt("bytes")} bytes)"
                    else "Export failed — ${res?.optString("reason") ?: "unknown"}",
                    Toast.LENGTH_LONG).show()
            }
        }
    }
}
