package com.ant.emichaosbg.ui

import android.content.Context
import android.graphics.Typeface
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.*

/**
 * THE APP SHELL — real navigation, native screens, and the WebView demoted to one destination
 * among several rather than being the entire application.
 *
 * WHAT CHANGED IN SHAPE. Until now MainActivity did `setContentView(webView)`: the app WAS the
 * page. Everything lived on one scroll, and "menus" meant tab buttons rendered in HTML inside
 * that single document. This puts a native menu above a native container and swaps real Views.
 *
 * THE WEBVIEW IS NOW A DESTINATION, AND ONLY WHERE IT EARNS IT:
 *
 *   - MASKER — Web Audio synthesis and the DOM hammer. The hammer disrupts a DOM, so it needs
 *     one; deleting the WebView would delete the feature. Audio moves when the synthesis engine
 *     is ported to AudioTrack, which is a large job and not this change.
 *   - It is also the instrumented attack surface. Hardening a WebView you have removed proves
 *     nothing, and the Frida/injection detection is most meaningful with a real JS bridge
 *     present to be attacked.
 *
 * Everything else renders natively from state that was ALREADY native. That is the part worth
 * stating plainly: this is not a rewrite of working logic, it is deleting a formatting layer.
 * ScanEngine, EscalationGuard, TapjackGuard, CellSecurity, NetGuard, TrackerWatch, BleWatcher,
 * TowerLog and SecureLog all already returned JSON; the page was reading it back out and
 * drawing numbers. Those numbers are now drawn where they are produced.
 *
 * WHERE THE MIGRATION STANDS. Security, Logs and Data are native Views. MASKER IS THE ONLY
 * REMAINING WEB-BACKED DESTINATION, and it is the one that should be: it hosts the audio graph
 * and the DOM hammer, and it is the attack surface the injection detection is there to watch.
 * DESTS carries that flag per destination so the shell can state it rather than imply it —
 * webBackedDestinations() is the honest answer to "how much of this is still a web page", and
 * it is now exactly one entry long.
 */
class ShellView(
    ctx: Context,
    private val webView: View,
    private val onDestinationChanged: (String) -> Unit = {}
) : LinearLayout(ctx) {

    private val content = FrameLayout(ctx)
    private val tabs = ArrayList<Button>()
    private val ui = Handler(Looper.getMainLooper())
    private var security: SecurityScreen? = null
    private var logs: LogsScreen? = null
    private var data: DataScreen? = null
    private var current = ""

    private val DESTS = listOf(
        "Masker" to true,      // true = still the WebView, and legitimately so
        "Security" to false,
        "Logs" to false,
        "Data" to false
    )

    init {
        orientation = VERTICAL
        setBackgroundColor(Nx.BG)

        // THE NAV BAR DIVIDES THE WIDTH; IT DOES NOT SCROLL.
        //
        // It was a HorizontalScrollView of wrap_content buttons, which meant the strip's width
        // was the sum of four labels plus padding — and at the user's font scale that sum
        // exceeded the screen, so DATA sat half off the right edge. A scrollable nav bar hides
        // destinations behind a gesture nobody thinks to make on something that looks like a
        // tab bar; it read as a broken layout, and it was one.
        //
        // Four destinations is a fixed, small set, so each simply takes a quarter of the width
        // and the LABEL shrinks to fit rather than the bar overflowing. Nothing can be pushed
        // off screen by a long label or a large font, because there is no off screen to be
        // pushed to.
        val strip = Nx.row(ctx).apply {
            setBackgroundColor(Nx.PANEL)
            setPadding(Nx.dp(ctx, 6), Nx.dp(ctx, 6), Nx.dp(ctx, 6), Nx.dp(ctx, 6))
        }
        DESTS.forEachIndexed { i, (name, _) ->
            val b = Button(ctx).apply {
                text = name
                isAllCaps = true
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setPadding(Nx.dp(ctx, 4), Nx.dp(ctx, 8), Nx.dp(ctx, 4), Nx.dp(ctx, 8))
                // Button carries a default minWidth that would re-inflate the row past the
                // screen even with weights applied.
                minWidth = 0; minimumWidth = 0
                maxLines = 1
                setOnClickListener { show(name) }
            }
            androidx.core.widget.TextViewCompat.setAutoSizeTextTypeUniformWithConfiguration(
                b, 8, 11, 1, android.util.TypedValue.COMPLEX_UNIT_SP
            )
            tabs.add(b)
            strip.addView(b, LinearLayout.LayoutParams(0, -2, 1f)
                .apply { if (i > 0) leftMargin = Nx.dp(ctx, 4) })
        }
        addView(strip, LayoutParams(-1, -2))
        addView(content, LayoutParams(-1, 0, 1f))

        show("Masker")

        // Native screens poll their own state rather than being pushed to. Slow on purpose:
        // these readings change on the order of minutes, and the freeze this app already had
        // came from exactly this kind of loop calling something expensive too often.
        ui.postDelayed(object : Runnable {
            override fun run() {
                when (current) {
                    "Security" -> security?.refresh(force = false)
                    "Data" -> data?.refresh()
                    // Logs deliberately absent: its refresh decrypts records.
                }
                ui.postDelayed(this, 5000)
            }
        }, 2500)
    }

    private fun show(name: String) {
        current = name
        tabs.forEach { b ->
            val on = b.text.toString().equals(name, true)
            b.setTextColor(if (on) Nx.PANEL else Nx.INK)
            b.setBackgroundColor(if (on) Nx.INK else android.graphics.Color.parseColor("#e6e1d4"))
        }
        content.removeAllViews()
        when (name) {
            "Security" -> {
                val s = security ?: SecurityScreen(context).also { security = it }
                content.addView(s, FrameLayout.LayoutParams(-1, -1))
                s.refresh(force = true)
            }
            "Logs" -> {
                val l = logs ?: LogsScreen(context).also { logs = it }
                content.addView(l, FrameLayout.LayoutParams(-1, -1))
                // Cheap only on entry. Loading records decrypts every one of them, so it stays
                // an explicit press — polling that is what froze this app before.
                l.refreshCheap()
            }
            "Data" -> {
                val d = data ?: DataScreen(context).also { data = it }
                content.addView(d, FrameLayout.LayoutParams(-1, -1))
                d.refresh()
            }
            else -> {
                // Still the page. Detaching and reattaching the same WebView preserves the
                // audio graph and the DOM hammer's state — recreating it would silently stop
                // the masker every time the user looked at another screen.
                (webView.parent as? android.view.ViewGroup)?.removeView(webView)
                content.addView(webView, FrameLayout.LayoutParams(-1, -1))
                onDestinationChanged(name)
            }
        }
    }

    /** Which destinations still render from the page, for an honest readout in the UI. */
    fun webBackedDestinations(): List<String> = DESTS.filter { it.second }.map { it.first }
}
