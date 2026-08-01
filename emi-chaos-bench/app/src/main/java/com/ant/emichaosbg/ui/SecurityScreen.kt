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
    private val escList: LinearLayout
    private val escTag: TextView
    private val tjTag: TextView
    private val netTag: TextView
    private val cellTag: TextView

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
            "Enabled ones are listed so an unexpected entry is obvious. THIS APP DOES NOT " +
            "REQUEST ONE: the capability it would grant is exactly what this app exists to warn " +
            "you about, and holding it would make this the most dangerous app on your device. " +
            "That is also why you will not find this app listed in the overlay or accessibility " +
            "screens — it asks for neither."))
        root.addView(tjCard)

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

    /** Pulled on a slow cadence by the shell, and on demand from the buttons. */
    fun refresh(force: Boolean) {
        val c = context
        runCatching {
            val g = MaskerService.ensureEscalationGuard(c)
            val o = JSONObject(if (force) g.scan() else g.cached())
            escTag.text = if (o.optBoolean("clean", true)) "clean" else "${o.optInt("count")} finding(s)"
            escVals[0].text = if (o.optBoolean("clean", true)) "clean" else "flagged"
            escVals[1].text = o.optInt("tracerPid", 0).let { if (it > 0) "PID $it" else "none" }
            escVals[2].text = o.opt("wxRegions")?.toString() ?: "—"
            escVals[3].text = o.opt("fileless")?.toString() ?: "—"
            escVals[4].text = o.optJSONArray("foreignLibs")?.length()?.toString() ?: "—"
            escVals[5].text = o.optString("selinux", "—")
            escList.removeAllViews()
            val f = o.optJSONArray("findings")
            if (f != null) for (i in 0 until f.length()) {
                val x = f.optJSONObject(i) ?: continue
                escList.addView(Nx.finding(c, x.optInt("sev", 1), x.optString("what"))
                    .apply { layoutParams = LinearLayout.LayoutParams(-1, -2)
                        .apply { topMargin = Nx.dp(c, 6) } })
            }
        }
        runCatching {
            val t = MaskerService.tapjackRef ?: return@runCatching
            val o = JSONObject(t.status())
            val blocked = o.optInt("filteredTouches", 0)
            tjTag.text = if (blocked > 0) "$blocked obscured" else "monitoring"
            tjVals[0].text = blocked.toString()
            tjVals[1].text = o.optInt("overlayCount", 0).toString()
            tjVals[2].text = o.optInt("a11yCount", 0).toString()
        }
        runCatching {
            val n = MaskerService.ensureNetGuard(c)
            val o = JSONObject(if (force) n.scan() else n.cached())
            if (o.optBoolean("ok", true)) {
                val dup = o.optJSONArray("duplicateMacs")?.length() ?: 0
                netTag.text = if (dup > 0) "$dup duplicate MAC(s)" else "nothing anomalous"
                netVals[0].text = o.optInt("arpEntries", 0).toString()
                netVals[1].text = dup.toString()
                netVals[2].text = o.optString("gatewayMac", "—")
                netVals[3].text = if (o.optBoolean("vpn")) "on" else "off"
                netVals[4].text = if (o.optBoolean("captivePortal")) "YES" else "no"
                netVals[5].text = o.optString("httpProxy", "").ifBlank { "none" }
            } else netTag.text = "not yet run"
        }
        runCatching {
            val cs = MaskerService.ensureCellSecurity(c)
            val o = JSONObject(if (force) cs.scan() else cs.cached())
            if (o.optBoolean("ok", true)) {
                val reg = o.optJSONObject("registered")
                val sec = o.optString("security", "unknown")
                cellTag.text = if (sec == "insecure") "INSECURE" else sec
                cellVals[0].text = reg?.optInt("gen")?.let { if (it > 0) "${it}G" else "none" } ?: "—"
                cellVals[1].text = sec
                cellVals[2].text = o.opt("neighbourCount")?.toString() ?: "—"
                cellVals[3].text = o.opt("dominanceDb")?.let { "$it dB" } ?: "—"
                cellVals[4].text = reg?.optLong("cid", -1)?.let { if (it >= 0) it.toString() else "—" } ?: "—"
                cellVals[5].text = reg?.optInt("area", -1)?.let { if (it >= 0) it.toString() else "—" } ?: "—"
            } else cellTag.text = "unavailable"
        }
    }
}
