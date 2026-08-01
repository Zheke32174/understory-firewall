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
 * MIGRATION, NOT A BIG BANG. Security is native here. Logs, Data and Masker still point at the
 * page while their screens are built, and the menu shows which is which rather than pretending
 * the move is finished.
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
    private var current = ""

    private val DESTS = listOf(
        "Masker" to true,      // true = still the WebView
        "Security" to false,
        "Logs" to true,
        "Data" to true
    )

    init {
        orientation = VERTICAL
        setBackgroundColor(Nx.BG)

        val bar = HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = false
            setBackgroundColor(Nx.PANEL)
        }
        val strip = Nx.row(ctx).apply { setPadding(Nx.dp(ctx, 6), Nx.dp(ctx, 6), Nx.dp(ctx, 6), Nx.dp(ctx, 6)) }
        DESTS.forEach { (name, _) ->
            val b = Button(ctx).apply {
                text = name
                isAllCaps = true
                textSize = 11f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setPadding(Nx.dp(ctx, 14), Nx.dp(ctx, 8), Nx.dp(ctx, 14), Nx.dp(ctx, 8))
                setOnClickListener { show(name) }
            }
            tabs.add(b)
            strip.addView(b, LinearLayout.LayoutParams(-2, -2)
                .apply { rightMargin = Nx.dp(ctx, 4) })
        }
        bar.addView(strip)
        addView(bar, LayoutParams(-1, -2))
        addView(content, LayoutParams(-1, 0, 1f))

        show("Masker")

        // Native screens poll their own state rather than being pushed to. Slow on purpose:
        // these readings change on the order of minutes, and the freeze this app already had
        // came from exactly this kind of loop calling something expensive too often.
        ui.postDelayed(object : Runnable {
            override fun run() {
                if (current == "Security") security?.refresh(force = false)
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
