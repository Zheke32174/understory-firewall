package com.ant.emichaosbg.ui

import android.content.Context
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.ant.emichaosbg.MaskerService
import org.json.JSONObject

/**
 * SECURITY — the first screen to leave the WebView entirely.
 *
 * Every number here was already produced natively; the page was only formatting it. Rendering
 * it in a native view removes the round-trip, removes the parse, and removes the possibility
 * that injected script alters what a security readout says on its way to the screen — which
 * for this screen in particular is the whole point. A compromise indicator rendered inside the
 * compartment being compromised is worth very little.
 *
 * It also removes a class of bug by construction: every string here quotes attacker-influenced
 * text (package labels, /proc paths, MAC addresses), and there is no markup parser anywhere in
 * a TextView. In the page, that safety depended on remembering to use textContent every time.
 */
class SecurityScreen(ctx: Context) : ScrollView(ctx) {

    private val escVals: List<TextView>
    private val tjVals: List<TextView>
    private val netVals: List<TextView>
    private val cellVals: List<TextView>
    private val wvVals: List<TextView>
    private val escList: LinearLayout
    private val escTag: TextView
    private val tjTag: TextView
    private val netTag: TextView
    private val cellTag: TextView
    private val wvTag: TextView

    init {
        setBackgroundColor(Nx.BG)
        val root = Nx.column(ctx, 10)
        addView(root)

        // ---- escalation ----
        val escCard = Nx.card(ctx)
        val (escHead, escT) = Nx.header(ctx, "Escalation guard"); escTag = escT
        escCard.addView(escHead)
        val escBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        escVals = Nx.statGrid(ctx, escBody, 3,
            listOf("Verdict", "Tracer", "W^X pages", "Fileless exec", "Injected libs", "SELinux"))
        escBody.addView(Nx.button(ctx, "Scan now") { refresh(force = true) }
            .apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
                .apply { topMargin = Nx.dp(ctx, 8) } })
        escList = Nx.column(ctx)
        escBody.addView(escList)
        escCard.addView(escBody)
        escCard.addView(Nx.body(ctx,
            "Looks for someone escalating AGAINST this app — code injected into its address " +
            "space, a tracer attached to its process, the sandbox not enforced, or a payload " +
            "running from memory with no file on disk.\n\n" +
            "This is not a root blocker. It does not care whether you rooted your own phone and " +
            "will not refuse to run if you did — that punishes the owner and stops no attacker. " +
            "The question is the opposite one: has anything got INSIDE this app.\n\n" +
            "Reports and never blocks. Retaliation is trivially bypassed by anyone who already " +
            "achieved injection, and a false positive would end a masking session you may be " +
            "relying on. An attacker with kernel control defeats every check here — this raises " +
            "the cost of a quiet compromise, it cannot prove there isn't one."))
        root.addView(escCard)

        // ---- tapjack / overlays ----
        val tjCard = Nx.card(ctx)
        val (tjHead, tjT) = Nx.header(ctx, "Overlays & accessibility"); tjTag = tjT
        tjCard.addView(tjHead)
        val tjBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        tjVals = Nx.statGrid(ctx, tjBody, 3,
            listOf("Obscured taps", "Overlay apps", "A11y services"))
        val tjRow = Nx.row(ctx).apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
            .apply { topMargin = Nx.dp(ctx, 8) } }
        tjRow.addView(Nx.button(ctx, "Overlay settings") {
            MaskerService.tapjackRef?.openOverlaySettings()
        }.apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        tjRow.addView(Nx.button(ctx, "Accessibility") {
            MaskerService.tapjackRef?.openAccessibilitySettings()
        }.apply { layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            .apply { leftMargin = Nx.dp(ctx, 6) } })
        tjBody.addView(tjRow)
        tjCard.addView(tjBody)
        tjCard.addView(Nx.body(ctx,
            "Another app draws a transparent window over this one; you believe you are tapping " +
            "a control here, but the touch lands on theirs — or theirs is lying about what the " +
            "control underneath does. It needs no root, only the overlay permission.\n\n" +
            "Obscured touches are DETECTED and reported. Blocking them is deliberately not the " +
            "default: the framework filter discards EVERY touch while any window overlays this " +
            "one, and blue-light filters, screen dimmers and chat bubbles all do that — with one " +
            "running, the app simply stops responding and you cannot reach the control that " +
            "would turn it off.\n\n" +
            "Accessibility services can read every screen and inject gestures — the most " +
            "powerful thing an app on Android can hold, and the usual home of stalkerware. " +
            "Enabled ones are listed so an unexpected entry is obvious.\n\n" +
            "THIS APP NOW APPEARS IN BOTH LISTS, and it did not before. That change is worth " +
            "stating plainly rather than leaving you to find it:\n\n" +
            "· Appear on top — the permission is DECLARED so the app is listed and can be " +
            "granted or refused like anything else. Nothing here draws an overlay on its own, " +
            "and the permission cannot be self-granted; only you can grant it, from that screen.\n\n" +
            "· Accessibility — 'Detect apps drawing on top of this one'. Optional, off until you " +
            "enable it. It exists because detecting an overlay from inside the app is not " +
            "reliably possible any other way: the window list belongs to the window manager. It " +
            "reads window METADATA ONLY — type, layer, position, size. It never reads screen " +
            "content, never sees what you type, and never blocks a touch.\n\n" +
            "Judge it the way you should judge any accessibility service, including this one: an " +
            "enabled service CAN be granted content access by the system, so the guarantee rests " +
            "on the code, which is in OverlayWatch.kt and calls no content API at all. If you do " +
            "not want that trade, leave it off — everything else on this screen works without it."))
        root.addView(tjCard)

        // ---- WebView provider ----
        val wvCard = Nx.card(ctx)
        val (wvHead, wvT) = Nx.header(ctx, "WebView provider"); wvTag = wvT
        wvCard.addView(wvHead)
        val wvBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        wvVals = Nx.statGrid(ctx, wvBody, 3, listOf("Package", "Version", "Channel"))
        wvCard.addView(wvBody)
        wvCard.addView(Nx.body(ctx,
            "Which WebView implementation is rendering the Masker screen. It matters twice.\n\n" +
            "FOR SECURITY: the WebView provider is swappable, and whatever provides it executes " +
            "every piece of script this app runs and parses every hostile string it meets — " +
            "network names, device names, cell identifiers. A provider that is not the expected " +
            "one, or one months out of date, is a larger change to this app's attack surface " +
            "than anything in its own code. Stock is com.google.android.webview (or " +
            "com.android.webview on AOSP builds).\n\n" +
            "FOR DEVELOPMENT: to debug or instrument the WebView, install a Dev-channel " +
            "WebView — the package is com.google.android.webview.dev — then choose it under " +
            "Developer options > WebView implementation. Only channels you have installed appear " +
            "in that list. This card is how you confirm the switch actually took effect, which " +
            "the Developer options screen alone does not tell you."))
        root.addView(wvCard)

        // ---- LAN ----
        val netCard = Nx.card(ctx)
        val (netHead, netT) = Nx.header(ctx, "LAN interception"); netTag = netT
        netCard.addView(netHead)
        val netBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        netVals = Nx.statGrid(ctx, netBody, 3,
            listOf("Devices", "Duplicate MACs", "Gateway MAC", "VPN", "Captive portal", "HTTP proxy"))
        netBody.addView(Nx.button(ctx, "Check now") { refresh(force = true) }
            .apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
                .apply { topMargin = Nx.dp(ctx, 8) } })
        netCard.addView(netBody)
        netCard.addView(Nx.body(ctx,
            "The detector for what ARP-spoofing tools DO. From the victim's side the attack " +
            "shows up in a table this device already keeps: one MAC answering for several IPs, " +
            "and the gateway's MAC changing while you stay on the same network.\n\n" +
            "Everything is a read. /proc/net/arp is the kernel's own table. No ARP is sent, no " +
            "packet injected, no host probed. It also does not probe a remote resolver or fetch " +
            "a canary to test for interception — that would mean this app generating traffic of " +
            "its own. Where a verdict is available it comes from Android's own network " +
            "validation, which costs nothing to read."))
        root.addView(netCard)

        // ---- cellular ----
        val cellCard = Nx.card(ctx)
        val (cellHead, cellT) = Nx.header(ctx, "Cellular security"); cellTag = cellT
        cellCard.addView(cellHead)
        val cellBody = Nx.column(ctx).apply { setPadding(Nx.dp(ctx, 8), 0, Nx.dp(ctx, 8), Nx.dp(ctx, 8)) }
        cellVals = Nx.statGrid(ctx, cellBody, 3,
            listOf("Connection", "Encryption", "Neighbours", "Dominance", "Cell ID", "Area code"))
        cellCard.addView(cellBody)
        cellCard.addView(Nx.body(ctx,
            "2G is the one that matters: GSM encryption is A5/1 (broken in practice) or A5/0 " +
            "(none at all), and 2G never authenticates the network to the handset — your phone " +
            "cannot tell a real tower from a fake one.\n\n" +
            "No public Android API exposes the cipher actually negotiated, so this reports what " +
            "the generation CAN offer, not what your baseband agreed to. Reading the real " +
            "negotiated cipher needs Qualcomm DIAG, root and a diag-capable ROM.\n\n" +
            "Nothing is switched automatically. No band forcing, no RAT locking — dropping a " +
            "phone off 2G at the wrong moment can cost an emergency call, which is worse than " +
            "being surveilled."))
        root.addView(cellCard)
    }

    /**
     * Gathers on a background thread and applies on the main one. Every call below blocks:
     * SecureLog's first use generates a Keystore key, EscalationGuard reads /proc/self/maps,
     * NetGuard reads /proc/net/arp, CellSecurity makes telephony binder calls. Doing that
     * inline is what froze this screen — the same mistake the page made, in Kotlin.
     */
    fun refresh(force: Boolean) {
        val c = context.applicationContext
        Async.load(this, {
            val out = HashMap<String, JSONObject?>()
            out["esc"] = runCatching {
                val g = MaskerService.ensureEscalationGuard(c)
                JSONObject(if (force) g.scan() else g.cached())
            }.getOrNull()
            out["tj"] = runCatching {
                MaskerService.tapjackRef?.let { JSONObject(it.status()) }
            }.getOrNull()
            out["net"] = runCatching {
                val n = MaskerService.ensureNetGuard(c)
                JSONObject(if (force) n.scan() else n.cached())
            }.getOrNull()
            out["cell"] = runCatching {
                val cs = MaskerService.ensureCellSecurity(c)
                JSONObject(if (force) cs.scan() else cs.cached())
            }.getOrNull()
            // WebView provider. getCurrentWebViewPackage() is a PackageManager lookup, so it
            // belongs off the main thread with everything else here.
            out["wv"] = runCatching {
                val p = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O)
                    android.webkit.WebView.getCurrentWebViewPackage() else null
                JSONObject()
                    .put("pkg", p?.packageName ?: "")
                    .put("ver", p?.versionName ?: "")
            }.getOrNull()
            out
        }, { out ->
            out["esc"]?.let { o ->
                // "clean" defaulting to TRUE was the bug: a report that has never been produced
                // must not read as an all-clear. Both the chip and the verdict now branch on
                // whether the check actually ran.
                val ran = o.optBoolean("ran", false)
                escTag.text = when {
                    !ran -> "NEVER RUN — not an all-clear"
                    o.optBoolean("clean") -> "clean"
                    else -> "${o.optInt("count")} finding(s)"
                }
                escVals[0].text = when {
                    !ran -> "not run"
                    o.optBoolean("clean") -> "clean"
                    else -> "flagged"
                }
                escVals[1].text = o.optInt("tracerPid", 0).let { if (it > 0) "PID $it" else "none" }
                escVals[2].text = o.opt("wxRegions")?.toString() ?: "\u2014"
                escVals[3].text = o.opt("fileless")?.toString() ?: "\u2014"
                escVals[4].text = o.optJSONArray("foreignLibs")?.length()?.toString() ?: "\u2014"
                escVals[5].text = o.optString("selinux", "\u2014")
                escList.removeAllViews()
                val f = o.optJSONArray("findings")
                if (f != null) for (i in 0 until f.length()) {
                    val x = f.optJSONObject(i) ?: continue
                    escList.addView(Nx.finding(context, x.optInt("sev", 1), x.optString("what")),
                        LinearLayout.LayoutParams(-1, -2).apply { topMargin = Nx.dp(context, 6) })
                }
            }
            out["tj"]?.let { o ->
                val blocked = o.optInt("filteredTouches", 0)
                // The dedicated detector's own state leads, because it is the one that can
                // actually see overlays; the counters below are the ambient view.
                val watching = com.ant.emichaosbg.OverlayWatch.connected
                tjTag.text = when {
                    blocked > 0 -> "$blocked obscured"
                    watching -> "overlay detection ON"
                    else -> "overlay detection off"
                }
                tjVals[0].text = blocked.toString()
                tjVals[1].text = o.optInt("overlayCount", 0).toString()
                tjVals[2].text = o.optInt("a11yCount", 0).toString()
            }
            out["wv"]?.let { o ->
                val pkg = o.optString("pkg")
                wvVals[0].text = if (pkg.isBlank()) "unknown" else pkg.substringAfterLast('.')
                wvVals[1].text = o.optString("ver").substringBefore('.').ifBlank { "—" }
                val channel = when {
                    pkg.endsWith(".dev") -> "DEV"
                    pkg.endsWith(".beta") -> "beta"
                    pkg.endsWith(".canary") -> "canary"
                    pkg == "com.google.android.webview" -> "stable"
                    pkg == "com.android.webview" -> "AOSP"
                    pkg.isBlank() -> "—"
                    else -> "other"
                }
                wvVals[2].text = channel
                wvTag.text = if (pkg.isBlank()) "not reported" else o.optString("ver").ifBlank { channel }
            }
            out["net"]?.let { o ->
                if (o.optBoolean("ok", true)) {
                    val dup = o.optJSONArray("duplicateMacs")?.length() ?: 0
                    /* THE ARP TABLE IS USUALLY UNREADABLE, AND THAT WAS BEING HIDDEN.
                     *
                     * NetGuard computes arpReadable and puts it in the JSON with a comment
                     * saying a silent empty result "reads as 'all good', which is the most
                     * dangerous thing a security readout can do" — and then this screen, its
                     * only consumer, dropped the field.
                     *
                     * On Android 10+ /proc/net/arp is unreadable to ordinary apps on most
                     * builds, so this is the DEFAULT state, not an edge case. With it
                     * unreadable there are no entries, so no duplicate MACs and no gateway MAC:
                     * both ARP-poisoning detections are structurally dead, and the card
                     * rendered "nothing anomalous / Devices 0 / Duplicate MACs 0" — pixel
                     * identical to a LAN that was examined and found clean.
                     */
                    if (!o.optBoolean("arpReadable", true)) {
                        netTag.text = "ARP TABLE UNREADABLE — LAN checks did not run"
                        netVals[0].text = "n/a"
                        netVals[1].text = "n/a"
                        netVals[2].text = "n/a"
                    } else {
                    netTag.text = if (dup > 0) "$dup duplicate MAC(s)" else "nothing anomalous"
                    netVals[0].text = o.optInt("arpEntries", 0).toString()
                    netVals[1].text = dup.toString()
                    netVals[2].text = o.optString("gatewayMac", "\u2014")
                    }
                    // VPN / captive portal / proxy come from the connectivity stack, not the
                    // ARP table, so they remain valid either way.
                    netVals[3].text = if (o.optBoolean("vpn")) "on" else "off"
                    netVals[4].text = if (o.optBoolean("captivePortal")) "YES" else "no"
                    netVals[5].text = o.optString("httpProxy", "").ifBlank { "none" }
                } else netTag.text = "not yet run"
            }
            out["cell"]?.let { o ->
                if (o.optBoolean("ok", true)) {
                    val reg = o.optJSONObject("registered")
                    val sec = o.optString("security", "unknown")
                    val simN = o.optInt("simCount", 0)
                    val eN = o.optInt("esimCount", 0)
                    cellTag.text = (if (sec == "insecure") "INSECURE" else sec) +
                        (if (simN > 1) "  ·  $simN SIMs" + (if (eN > 0) " ($eN eSIM)" else "") else "")
                    cellVals[0].text = reg?.optInt("gen")?.let { if (it > 0) "${it}G" else "none" } ?: "\u2014"
                    cellVals[1].text = sec
                    cellVals[2].text = o.opt("neighbourCount")?.toString() ?: "\u2014"
                    cellVals[3].text = o.opt("dominanceDb")?.let { "$it dB" } ?: "\u2014"
                    cellVals[4].text = reg?.optLong("cid", -1)?.let { if (it >= 0) it.toString() else "\u2014" } ?: "\u2014"
                    cellVals[5].text = reg?.optInt("area", -1)?.let { if (it >= 0) it.toString() else "\u2014" } ?: "\u2014"
                } else cellTag.text = "unavailable"
            }
        })
    }
}
