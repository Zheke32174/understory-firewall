package com.ant.emichaosbg.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.ant.emichaosbg.core.Sentinel
import org.json.JSONObject

/**
 * SWEEP — the home screen, and the answer to "does pressing one thing produce
 * results".
 *
 * One button runs every on-demand detector in this app and every card below shows
 * what it concluded, with a nav hint to the screen that has the detail. Nothing
 * here is a summary of a summary: each row is read from that detector's own last
 * result object, and a detector that has not run says "not yet run" rather than
 * rendering a zero.
 */
@Composable
fun SweepScreen(
    padding: PaddingValues,
    onGo: (OrbRoute) -> Unit,
) {
    val sweep = rememberProbe(autoRun = false) { Sentinel.sweepBlocking() }
    val status = rememberProbe { Sentinel.status() }

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = padding,
    ) {
        item {
            OrbCard {
                CardHeader(
                    "Sentinel",
                    if (Sentinel.isDetecting()) "running" else "stopped",
                    if (Sentinel.isDetecting()) Level.OK else Level.ALERT,
                )
                val s = status.json
                KeyValue("Wi-Fi sweep", if (Sentinel.isDetecting()) "continuous" else "off")
                KeyValue("BLE scan", if (Sentinel.isDetecting()) "continuous" else "off")
                KeyValue("Slow sweeps", s?.optLong("slowSweeps")?.toString() ?: "—")
                KeyValue("Tower samples", s?.optLong("towerSamples")?.toString() ?: "—")
                KeyValue("Masking", if (s?.optBoolean("masking") == true) "on" else "off")
                KeyValue("Mic monitor", if (s?.optBoolean("micRunning") == true) "on" else "off")
                Note(
                    "Detection starts from this app's own first frame and keeps running in a " +
                        "foreground service. It is not gated on the masker, on a web page, or on " +
                        "any other app being installed."
                )
                Row(
                    Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    RunButton("Run every detector", sweep.busy) {
                        sweep.refresh(); status.refresh()
                    }
                    SecondaryButton("Refresh") { status.refresh() }
                }
            }
        }

        item {
            Column {
            SectionHeader("Last sweep")
            if (!sweep.ran) {
                OrbCard {
                    CardHeader("No sweep yet", "not run", Level.UNKNOWN)
                    Note(
                        "Nothing has been looked at on demand yet. That is NOT an all-clear. " +
                            "Press Run every detector above — it takes a few seconds because it " +
                            "reads /proc, the telephony binder, the ARP table and the package " +
                            "list for real."
                    )
                }
            }
            }
        }

        sweep.json?.let { r ->
            item { SweepRow("Process integrity", escalationVerdict(r.optJSONObject("escalation")), OrbRoute.DEVICE, onGo) }
            item { SweepRow("App integrity", integrityVerdict(r.optJSONObject("integrity")), OrbRoute.DEVICE, onGo) }
            item { SweepRow("Overlays & accessibility", overlayVerdict(r.optJSONObject("overlays")), OrbRoute.DEVICE, onGo) }
            item { SweepRow("Cellular", cellVerdict(r.optJSONObject("cell")), OrbRoute.RADIOS, onGo) }
            item { SweepRow("LAN interception", netVerdict(r.optJSONObject("net")), OrbRoute.RADIOS, onGo) }
            item { SweepRow("Wi-Fi", wifiVerdict(r.optJSONObject("wifi")), OrbRoute.RADIOS, onGo) }
            item { SweepRow("BLE followers", bleVerdict(r.optJSONObject("ble"), r.optJSONObject("tracker")), OrbRoute.RADIOS, onGo) }
        }

        sweep.error?.let {
            item {
                OrbCard {
                    CardHeader("Sweep failed", "error", Level.ALERT)
                    Note(it)
                }
            }
        }

        item {
            Column {
            SectionHeader("What this app is")
            OrbCard {
                Text(
                    "Chaos Orb runs counter-surveillance detectors against THIS phone's own " +
                        "radios, process and sensors, records every finding into a tamper-evident " +
                        "encrypted vault, and masks audio. Everything reports; nothing blocks, " +
                        "jams, transmits or retaliates.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Note(
                    "This build holds no INTERNET permission, contains no WebView and no " +
                        "JavaScript bridge, and depends on no other app. Every heuristic here has " +
                        "legitimate causes and is worded as a reason to look, never as a verdict."
                )
            }
            }
        }
    }
}

@Composable
private fun SweepRow(
    title: String,
    v: Verdict,
    route: OrbRoute,
    onGo: (OrbRoute) -> Unit,
) {
    OrbCard {
        CardHeader(title, v.label, v.level)
        Note(v.detail)
        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.sm),
            horizontalArrangement = Arrangement.End,
        ) {
            SecondaryButton("Open ${route.title}") { onGo(route) }
        }
    }
}

// ---------------------------------------------------------------- verdict mapping

data class Verdict(val label: String, val level: Level, val detail: String)

private val NOT_RUN = Verdict(
    "not run", Level.UNKNOWN,
    "This detector produced no result in the last sweep. Never-run is not an all-clear."
)

private fun escalationVerdict(o: JSONObject?): Verdict {
    if (o == null || !o.optBoolean("ran")) return NOT_RUN
    val n = o.optInt("count")
    return if (n == 0) Verdict("clean", Level.OK,
        "No tracer attached, no writable-executable pages, no fileless code, no foreign " +
            "libraries and no injection framework mapped into this process.")
    else Verdict("$n finding${if (n == 1) "" else "s"}", Level.ALERT,
        "Something about this process's address space or sandbox is not what it should be.")
}

private fun integrityVerdict(o: JSONObject?): Verdict {
    if (o == null || !o.optBoolean("ran")) return NOT_RUN
    if (!o.optBoolean("signaturePinned")) return Verdict("not pinned", Level.WARN,
        "No expected certificate digest is compiled into this build, so the signature check is " +
            "inactive.")
    val n = o.optInt("count")
    return if (n == 0) Verdict("signed + clean", Level.OK,
        "This APK is signed by the pinned suite certificate and nothing is instrumenting it.")
    else Verdict("$n finding${if (n == 1) "" else "s"}", Level.ALERT, o.optJSONArray("findings")
        ?.optString(0) ?: "See App integrity.")
}

private fun overlayVerdict(o: JSONObject?): Verdict {
    if (o == null) return NOT_RUN
    val overlays = o.optInt("overlayCount")
    val a11y = o.optInt("a11yCount")
    val level = when {
        a11y > 0 -> Level.WARN
        overlays > 0 -> Level.INFO
        else -> Level.OK
    }
    return Verdict("$overlays over · $a11y a11y", level,
        "$overlays app(s) are allowed to draw on top of this one and $a11y accessibility " +
            "service(s) are enabled. Neither is wrongdoing on its own — both are the capability " +
            "tapjacking and stalkerware need.")
}

private fun cellVerdict(o: JSONObject?): Verdict {
    if (o == null) return NOT_RUN
    if (!o.optBoolean("ok", true)) return Verdict("unavailable", Level.UNKNOWN,
        o.optString("reason", "cellular state could not be read"))
    val sec = o.optString("security", "unknown")
    val level = when (sec) {
        "insecure" -> Level.ALERT
        "weak" -> Level.WARN
        "ok" -> Level.OK
        else -> Level.UNKNOWN
    }
    val reg = o.optJSONObject("registered")
    return Verdict(sec, level,
        "Registered on ${reg?.optString("kind") ?: "no cell"} across " +
            "${o.optInt("simCount")} subscription(s), ${o.optInt("neighbourCount")} neighbour(s) " +
            "visible. The verdict is taken from the WEAKEST subscription.")
}

private fun netVerdict(o: JSONObject?): Verdict {
    if (o == null) return NOT_RUN
    val arp = o.optBoolean("arpReadable")
    val dupes = o.optJSONArray("duplicateMacs")?.length() ?: 0
    val portal = o.optBoolean("captivePortal")
    return when {
        portal -> Verdict("portal", Level.ALERT,
            "This network intercepts traffic and redirects it to a portal — equipment that has " +
                "already demonstrated it will rewrite what you send.")
        dupes > 0 -> Verdict("$dupes duplicate MAC", Level.WARN,
            "One device is answering for several IP addresses — the shape ARP poisoning leaves.")
        !arp -> Verdict("arp unreadable", Level.UNKNOWN,
            "/proc/net/arp could not be read, which is the DEFAULT on most Android 10+ builds. " +
                "The LAN-poisoning checks did not run; the resolver, proxy and VPN checks did.")
        else -> Verdict("clean", Level.OK,
            "ARP table readable and consistent, no duplicate MACs, no captive portal.")
    }
}

private fun wifiVerdict(o: JSONObject?): Verdict {
    if (o == null) return NOT_RUN
    if (!o.optBoolean("running")) return Verdict("stopped", Level.UNKNOWN, o.optString("why"))
    val nets = o.optInt("networks")
    val findings = o.optLong("findings")
    return when {
        nets == 0 -> Verdict("no results", Level.UNKNOWN, o.optString("why"))
        findings > 0 -> Verdict("$findings finding(s)", Level.WARN,
            "$nets network(s) in range across ${o.optLong("wifiScans")} scans. Open Radios for " +
                "the rogue-AP, evil-twin and Karma detail.")
        else -> Verdict("clean", Level.OK,
            "$nets network(s) in range across ${o.optLong("wifiScans")} scans, nothing raised.")
    }
}

private fun bleVerdict(status: JSONObject?, tracker: JSONObject?): Verdict {
    if (status == null) return NOT_RUN
    if (!status.optBoolean("running")) return Verdict("stopped", Level.UNKNOWN,
        status.optString("error", "the BLE scan is not running"))
    val tracked = tracker?.optInt("tracked") ?: 0
    val cands = tracker?.optJSONArray("candidates")
    var following = 0
    var camped = 0
    if (cands != null) for (i in 0 until cands.length()) {
        val c = cands.optJSONObject(i) ?: continue
        if (c.optBoolean("following")) following++
        if (c.optBoolean("camped")) camped++
    }
    return when {
        following > 0 -> Verdict("$following following", Level.ALERT,
            "A device has stayed with you across separate scans AND over real distance.")
        camped > 0 -> Verdict("$camped camped", Level.WARN,
            "$camped device(s) have sat beside you across many scans while you did not move.")
        else -> Verdict("$tracked tracked", Level.OK,
            "$tracked identities in the last hour, none meeting the follow or camp thresholds.")
    }
}
