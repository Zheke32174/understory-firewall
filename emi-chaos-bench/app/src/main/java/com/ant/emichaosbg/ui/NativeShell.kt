package com.ant.emichaosbg.ui

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.*

/**
 * NATIVE UI TOOLKIT — the beginning of the app stopping being an HTML page.
 *
 * WHERE THIS CAME FROM. The app grew as one large index.html because that is how it started,
 * and every feature since was appended to it. The result reads exactly like what it is: a
 * single scrolling document with more and more bolted on, in which the audio masker, the
 * evidence vault and the escalation detector are all just further down the same page.
 *
 * THE TARGET SHAPE. Native screens with real navigation, and a WebView kept ONLY for the parts
 * that genuinely require one:
 *
 *   - the DOM hammer, which disrupts a DOM and therefore needs a DOM to disrupt;
 *   - the WebView attack surface itself, which is the thing being defended and instrumented —
 *     you cannot test your hardening of a component you have deleted;
 *   - Web Audio, until the synthesis engine is ported to AudioTrack.
 *
 * Everything else is already native underneath. ScanEngine, EscalationGuard, TapjackGuard,
 * CellSecurity, NetGuard, TrackerWatch, BleWatcher, TowerLog and SecureLog all expose JSON
 * today and none of them need a browser to render a number. The page had become a viewer over
 * native state, which is the least useful place for a viewer to live: it is the compartment
 * hostile script reaches first and the OS destroys first.
 *
 * NO NEW DEPENDENCIES. Plain Views built in code rather than Compose or Material — this app
 * ships to people who have reason to care what is inside it, and a UI framework is a large
 * amount of code to add for a screen that displays text and numbers. Everything here is
 * android.widget.
 */
object Nx {

    // Matches the page's palette so the native screens and the remaining WebView do not look
    // like two different applications during the migration.
    val BG = Color.parseColor("#cfcabc")
    val PANEL = Color.parseColor("#dcd7c9")
    val INK = Color.parseColor("#23201b")
    val SOFT = Color.parseColor("#5c5749")
    val RULE = Color.parseColor("#a9a290")
    val ACCENT = Color.parseColor("#2c6f68")
    val WARN = Color.parseColor("#d68910")
    val CRIT = Color.parseColor("#c0392b")

    fun dp(ctx: Context, v: Int) = (v * ctx.resources.displayMetrics.density).toInt()

    fun column(ctx: Context, pad: Int = 0): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            if (pad > 0) setPadding(dp(ctx, pad), dp(ctx, pad), dp(ctx, pad), dp(ctx, pad))
        }

    fun row(ctx: Context): LinearLayout =
        LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL }

    /** Section heading with an optional right-aligned status chip. */
    fun header(ctx: Context, title: String): Pair<LinearLayout, TextView> {
        val bar = row(ctx).apply {
            setBackgroundColor(PANEL)
            setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10))
            gravity = Gravity.CENTER_VERTICAL
        }
        bar.addView(TextView(ctx).apply {
            text = title.uppercase()
            setTextColor(INK); textSize = 13f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            letterSpacing = 0.08f
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        })
        val tag = TextView(ctx).apply {
            setTextColor(SOFT); textSize = 9f
            typeface = Typeface.MONOSPACE
            letterSpacing = 0.06f
        }
        bar.addView(tag)
        return bar to tag
    }

    /** A labelled value cell. Returns the value view so the screen can update it. */
    fun stat(ctx: Context, label: String): Pair<LinearLayout, TextView> {
        val box = column(ctx).apply {
            setBackgroundColor(Color.parseColor("#e6e1d4"))
            setPadding(dp(ctx, 9), dp(ctx, 7), dp(ctx, 9), dp(ctx, 8))
        }
        box.addView(TextView(ctx).apply {
            text = label.uppercase(); setTextColor(SOFT); textSize = 8.5f
            typeface = Typeface.MONOSPACE; letterSpacing = 0.07f
        })
        val v = TextView(ctx).apply {
            text = "—"; setTextColor(INK); textSize = 17f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        }
        box.addView(v)
        return box to v
    }

    /** Grid of stat cells, [cols] per row. Returns the value views in order. */
    fun statGrid(ctx: Context, parent: LinearLayout, cols: Int, labels: List<String>): List<TextView> {
        val out = ArrayList<TextView>()
        var r: LinearLayout? = null
        labels.forEachIndexed { i, label ->
            if (i % cols == 0) {
                r = row(ctx).apply {
                    layoutParams = LinearLayout.LayoutParams(-1, -2)
                        .apply { topMargin = dp(ctx, 6) }
                }
                parent.addView(r)
            }
            val (box, v) = stat(ctx, label)
            box.layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                .apply { if (i % cols != 0) leftMargin = dp(ctx, 6) }
            r!!.addView(box)
            out.add(v)
        }
        return out
    }

    fun body(ctx: Context, text: String): TextView =
        TextView(ctx).apply {
            this.text = text
            setTextColor(SOFT); textSize = 11.5f
            typeface = Typeface.MONOSPACE
            setLineSpacing(dp(ctx, 3).toFloat(), 1f)
            setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 12))
        }

    fun button(ctx: Context, label: String, onClick: () -> Unit): Button =
        Button(ctx).apply {
            text = label
            isAllCaps = true
            setTextColor(INK); textSize = 10.5f
            typeface = Typeface.MONOSPACE
            setBackgroundColor(Color.parseColor("#e6e1d4"))
            setOnClickListener { onClick() }
        }

    /**
     * A finding row. Text is set with setText on a TextView — there is no markup parser
     * anywhere in this path, which is a property worth having for free: these strings quote
     * scanned SSIDs, package labels and /proc paths, all of which are attacker-influenceable.
     * In the page that safety had to be maintained by remembering to use textContent.
     */
    fun finding(ctx: Context, severity: Int, text: String): TextView =
        TextView(ctx).apply {
            this.text = text
            setTextColor(INK); textSize = 11f
            typeface = Typeface.MONOSPACE
            setLineSpacing(dp(ctx, 3).toFloat(), 1f)
            setPadding(dp(ctx, 10), dp(ctx, 8), dp(ctx, 10), dp(ctx, 8))
            setBackgroundColor(Color.parseColor("#e9e4d7"))
            val stripe = when {
                severity >= 3 -> CRIT
                severity == 2 -> WARN
                else -> RULE
            }
            // Left severity stripe, drawn as a layered background rather than an extra view.
            background = android.graphics.drawable.LayerDrawable(arrayOf(
                android.graphics.drawable.ColorDrawable(stripe),
                android.graphics.drawable.InsetDrawable(
                    android.graphics.drawable.ColorDrawable(Color.parseColor("#e9e4d7")),
                    dp(ctx, 3), 0, 0, 0)
            ))
        }

    fun spacer(ctx: Context, h: Int): View =
        View(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, dp(ctx, h)) }

    fun card(ctx: Context): LinearLayout =
        column(ctx).apply {
            setBackgroundColor(Color.parseColor("#d5d0c1"))
            layoutParams = LinearLayout.LayoutParams(-1, -2)
                .apply { bottomMargin = dp(ctx, 10) }
        }
}
