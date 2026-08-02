package com.ant.emichaosbg.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.ant.emichaosbg.WifiScanBudget
import com.ant.emichaosbg.core.Sentinel
import org.json.JSONArray
import org.json.JSONObject

/**
 * RADIOS — every detector that reads a radio, each with its own Run control and
 * its own live result, on one screen that is one tap from the app's first frame.
 *
 * In the previous build ScanEngine — the entire Wi-Fi rogue-AP / evil-twin / Karma
 * detector — had NO native screen anywhere. It was the single biggest "scanner
 * with no caller". It is the first card here.
 */
@Composable
fun RadiosScreen(padding: PaddingValues) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
        item { Column { SectionHeader("Wi-Fi"); WifiCard() } }
        item { Column { SectionHeader("Bluetooth LE"); BleCard() } }
        item { Column { SectionHeader("Cellular"); CellCard() } }
        item { Column { SectionHeader("Local network"); LanCard() } }
        item { Column { SectionHeader("Tower + position log"); TowerCard() } }
    }
}

// ------------------------------------------------------------------ Wi-Fi

@Composable
private fun WifiCard() {
    val snap = rememberProbe { Sentinel.wifi.snapshot() }
    val nets = rememberProbe { "{\"nets\":" + Sentinel.wifi.lastWifiJson() + "}" }
    val budget = rememberProbe { WifiScanBudget.state() }
    val act = rememberAction()

    OrbCard {
        val o = snap.json
        val running = o?.optBoolean("running") == true
        CardHeader("Rogue AP / evil twin / Karma", if (running) "scanning" else "stopped",
            if (running) Level.OK else Level.WARN)

        KeyValue("Networks in range", o?.optInt("networks")?.toString() ?: "—")
        KeyValue("Scans completed", o?.optLong("wifiScans")?.toString() ?: "—")
        KeyValue("Findings stored", o?.optLong("findings")?.toString() ?: "—")
        KeyValue("BSSIDs remembered", o?.optInt("knownBssids")?.toString() ?: "—")
        KeyValue("Location switch", if (o?.optBoolean("locationEnabled") == true) "on" else "OFF",
            if (o?.optBoolean("locationEnabled") == true) Level.OK else Level.ALERT)
        KeyValue("Precise location", if (o?.optBoolean("fineLocation") == true) "granted" else "NOT granted",
            if (o?.optBoolean("fineLocation") == true) Level.OK else Level.ALERT)

        o?.optString("why")?.takeIf { it.isNotBlank() }?.let { Note("Why: $it") }
        o?.optString("storeWarning")?.takeIf { it.isNotBlank() }
            ?.let { Finding(it, Level.ALERT) }
        o?.optString("error")?.takeIf { it.isNotBlank() }?.let { Finding(it, Level.ALERT) }

        ThinDivider()
        val b = budget.json
        KeyValue("Scan budget", if (b == null) "—"
        else "${b.optInt("used")}/${b.optInt("max")} used · ${b.optInt("reserved")} reserved")
        Note(
            "Android allows about four scan STARTS per two minutes per app and drops the rest " +
                "silently. Only the START is throttled — reading the platform's cached results is " +
                "free, so a denied start costs freshness, not data."
        )

        ThinDivider()
        val arr = nets.json?.optJSONArray("nets")
        if (arr != null && arr.length() > 0) {
            val (ssidVendors, ssidBssids) = aggregate(arr)
            var flagged = 0
            for ((ssid, vendors) in ssidVendors) {
                if (vendors < 2) continue
                flagged++
                Finding(
                    "\"$ssid\" is broadcast from $vendors different vendor MAC prefixes — " +
                        "possible rogue/evil-twin AP, or a legitimate mixed-vendor mesh.",
                    Level.WARN,
                )
            }
            for ((ssid, count) in ssidBssids) {
                if (count < 6) continue
                flagged++
                Finding(
                    "\"$ssid\" answers on $count distinct BSSIDs at once — more radios than a " +
                        "typical mesh. Can indicate a Karma-style responder. Large venues do this " +
                        "legitimately.",
                    Level.WARN,
                )
            }
            if (flagged == 0) Note("No SSID in range is showing the evil-twin or Karma shape.")
        } else {
            Note("No scan results to analyse yet.")
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Scan now", act.busy) {
                // A REAL user-priority sweep. scanNow() runs the gated startScan() at
                // critical priority off the main thread — so a reserved slot is spent only
                // when the radio is actually asked — then the read-only probes re-render its
                // result once it returns.
                act.go {
                    Sentinel.wifi.scanNow()
                    snap.refresh(); nets.refresh(); budget.refresh()
                    "fresh sweep requested"
                }
            }
            SecondaryButton(if (Sentinel.wifi.isRunning()) "Stop sweep" else "Start sweep") {
                if (Sentinel.wifi.isRunning()) Sentinel.wifi.stop() else Sentinel.wifi.start()
                snap.refresh()
            }
        }
        act.result?.let { Note("Radio: $it") }
    }
}

private fun aggregate(arr: JSONArray): Pair<Map<String, Int>, Map<String, Int>> {
    val vendors = HashMap<String, MutableSet<String>>()
    val bssids = HashMap<String, MutableSet<String>>()
    for (i in 0 until arr.length()) {
        val o = arr.optJSONObject(i) ?: continue
        val ssid = o.optString("ssid", "")
        val bssid = o.optString("bssid", "").lowercase()
        if (ssid.isBlank() || bssid.length < 8) continue
        vendors.getOrPut(ssid) { HashSet() }.add(bssid.substring(0, 8))
        bssids.getOrPut(ssid) { HashSet() }.add(bssid)
    }
    return vendors.mapValues { it.value.size } to bssids.mapValues { it.value.size }
}

// ------------------------------------------------------------------ BLE

@Composable
private fun BleCard() {
    val status = rememberProbe { Sentinel.ble.status() }
    val stats = rememberProbe { Sentinel.tracker.stats() }
    val act = rememberAction()
    var shown by remember { mutableIntStateOf(8) }

    OrbCard {
        val s = status.json
        val running = s?.optBoolean("running") == true
        CardHeader("Follower / tracker detection", if (running) "scanning" else "stopped",
            if (running) Level.OK else Level.WARN)

        KeyValue("Sightings", s?.optLong("sightings")?.toString() ?: "—")
        KeyValue("Scan windows", s?.optLong("flushes")?.toString() ?: "—")
        KeyValue("In range now", s?.optInt("buffered")?.toString() ?: "—")
        val err = s?.optString("error", "") ?: ""
        if (err.isNotBlank()) {
            KeyValue("Radio", err, Level.ALERT)
            Note(
                "\"No tracker is following you\" and \"this never looked\" must never be the same " +
                    "words on screen. The line above is why nothing is being seen."
            )
        }

        val t = stats.json
        KeyValue("Identities tracked", t?.optInt("tracked")?.toString() ?: "—")
        KeyValue("Scan sessions", t?.optLong("sessions")?.toString() ?: "—")

        ThinDivider()
        val cands = t?.optJSONArray("candidates")
        if (cands == null || cands.length() == 0) {
            Note(
                "Nothing has been seen across enough separate scan sessions to say anything yet. " +
                    "A FOLLOW needs six sessions AND 500m of travel; CAMPED needs twelve sessions " +
                    "over fifteen minutes while you stay put."
            )
        } else {
            val rows = (0 until cands.length()).mapNotNull { cands.optJSONObject(it) }
                .sortedByDescending { it.optInt("sessions") }
            rows.take(shown).forEach { c ->
                val following = c.optBoolean("following")
                val camped = c.optBoolean("camped")
                val level = when {
                    following -> Level.ALERT
                    camped -> Level.WARN
                    else -> Level.INFO
                }
                val tag = when {
                    following -> "FOLLOWING"
                    camped -> "CAMPED"
                    else -> "seen"
                }
                Finding(
                    "$tag · ${c.optString("label", "unidentified")} · " +
                        "${c.optInt("sessions")} sessions · ${c.optLong("minutes")} min · " +
                        "moved ${c.optInt("movedM")}m · ${c.optInt("rssi")}dBm · " +
                        "${c.optInt("addresses")} address(es) · ${c.optString("addrClass")}" +
                        if (c.optBoolean("staticAddr")) " · STATIC ADDRESS" else "",
                    level,
                )
            }
            if (rows.size > shown) {
                SecondaryButton("Show all ${rows.size}") { shown = rows.size }
            }
            Note(
                "A STATIC ADDRESS is the discriminator: modern phones and wearables use " +
                    "resolvable private addresses and rotate them every few minutes, so one " +
                    "address held throughout is the signature of installed equipment rather than " +
                    "someone walking past. Anything mains-powered nearby looks like this."
            )
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Refresh", status.busy) { status.refresh(); stats.refresh() }
            SecondaryButton(if (running) "Stop scan" else "Start scan") {
                act.go {
                    if (Sentinel.ble.isRunning()) { Sentinel.ble.stop(); "stopped" }
                    else Sentinel.ble.start()
                }
                status.refresh(); stats.refresh()
            }
            SecondaryButton("Flush window") {
                act.go { "handed " + Sentinel.ble.flush() + " sighting(s) to the analyser" }
                stats.refresh()
            }
        }
        act.result?.let { Note("Radio: $it") }
    }
}

// ------------------------------------------------------------------ Cellular

@Composable
private fun CellCard() {
    // "Check now" must MEASURE, not re-read. cell.scan() does a live TelephonyManager.allCellInfo
    // read (receive-only) and runs the downgrade / IMSI-catcher heuristics on it; cell.cached()
    // only returned the last timer-driven scan's stored output, so the button asserted a fresh
    // look that never happened. Probe runs this on Dispatchers.IO, so the @Synchronized live read
    // never blocks the frame, and probe.refresh() from the button re-measures on demand.
    val probe = rememberProbe { Sentinel.cell.scan() }

    OrbCard {
        val o = probe.json
        val ok = o != null && o.optBoolean("ok", true) && o.has("registered")
        val sec = o?.optString("security", "unknown") ?: "unknown"
        CardHeader("Downgrade / IMSI-catcher heuristics",
            if (!ok) "not run" else sec,
            when {
                !ok -> Level.UNKNOWN
                sec == "insecure" -> Level.ALERT
                sec == "weak" -> Level.WARN
                sec == "ok" -> Level.OK
                else -> Level.UNKNOWN
            })

        if (o != null && !o.optBoolean("ok", true)) {
            Note(o.optString("reason", "cellular state could not be read"))
        } else if (o != null && ok) {
            val reg = o.optJSONObject("registered")
            KeyValue("Serving cell", reg?.optString("kind") ?: "none")
            KeyValue("Cell id", reg?.optLong("cid")?.toString() ?: "—")
            KeyValue("Area code", reg?.optInt("area")?.toString() ?: "—")
            KeyValue("Signal", reg?.optInt("dbm")?.let { "$it dBm" } ?: "—")
            KeyValue("Neighbours", o.optInt("neighbourCount").toString())
            if (o.has("dominanceDb")) KeyValue("Dominance", "${o.optInt("dominanceDb")} dB")
            KeyValue("No-neighbour runs", o.optInt("noNeighbourRuns").toString())

            val sims = o.optJSONArray("sims")
            if (sims != null) for (i in 0 until sims.length()) {
                val s = sims.optJSONObject(i) ?: continue
                KeyValue(
                    "SIM ${s.optInt("slot")}",
                    "${s.optString("kind")} · ${s.optString("carrier")} · ${s.optInt("gen")}G",
                )
            }
            o.optString("multiSimNote").takeIf { it.isNotBlank() }?.let { Note(it) }
            Note(o.optString("securityNote"))

            ThinDivider()
            val limits = o.optJSONArray("limits")
            if (limits != null) for (i in 0 until limits.length()) {
                Finding(limits.optString(i), Level.INFO)
            }
        } else {
            Note(
                "This check has not produced a result yet. It runs on the sentinel's five-minute " +
                    "timer, or immediately from the button below."
            )
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Check now", probe.busy) { probe.refresh() }
        }
    }
}

// ------------------------------------------------------------------ LAN

@Composable
private fun LanCard() {
    val probe = rememberProbe { Sentinel.net.cached() }
    var deep by remember { mutableStateOf(false) }

    OrbCard {
        val o = probe.json
        val ran = o != null && o.has("arpReadable")
        val dupes = o?.optJSONArray("duplicateMacs")?.length() ?: 0
        CardHeader(
            "ARP poisoning / interception posture",
            when {
                !ran -> "not run"
                o!!.optBoolean("captivePortal") -> "portal"
                dupes > 0 -> "$dupes duplicate"
                !o.optBoolean("arpReadable") -> "arp unreadable"
                else -> "clean"
            },
            when {
                !ran -> Level.UNKNOWN
                o!!.optBoolean("captivePortal") -> Level.ALERT
                dupes > 0 -> Level.WARN
                !o.optBoolean("arpReadable") -> Level.UNKNOWN
                else -> Level.OK
            },
        )

        if (!ran) {
            Note("Not run yet. Press Check now.")
        } else {
            val arp = o!!.optBoolean("arpReadable")
            KeyValue("/proc/net/arp", if (arp) "readable" else "NOT readable",
                if (arp) Level.OK else Level.UNKNOWN)
            if (!arp) Note(
                "Android 10+ restricts /proc/net on most builds — this is the DEFAULT state, not " +
                    "a fault. The ARP-poisoning checks did not run. Everything below it did, " +
                    "because it comes from LinkProperties and NetworkCapabilities instead."
            )
            KeyValue("ARP entries", o.optInt("arpEntries").toString())
            KeyValue("Gateway", o.optString("gatewayIp", "unknown"))
            KeyValue("Gateway MAC", o.optString("gatewayMac", "unknown"))
            KeyValue("Interface", o.optString("iface", ""))
            KeyValue("Validated", if (o.optBoolean("validated")) "yes" else "no",
                if (o.optBoolean("validated")) Level.OK else Level.WARN)
            KeyValue("Captive portal", if (o.optBoolean("captivePortal")) "YES" else "no",
                if (o.optBoolean("captivePortal")) Level.ALERT else Level.OK)
            KeyValue("HTTP proxy", o.optString("httpProxy", "").ifBlank { "none" },
                if (o.optString("httpProxy", "").isBlank()) Level.OK else Level.WARN)
            KeyValue("Private DNS", if (o.optBoolean("dnsEncrypted")) "on" else "off",
                if (o.optBoolean("dnsEncrypted")) Level.OK else Level.WARN)
            KeyValue("VPN", if (o.optBoolean("vpn")) "yes" else "no")

            val dns = o.optJSONArray("dnsServers")
            if (dns != null && dns.length() > 0) {
                KeyValue("Resolvers", (0 until dns.length()).joinToString(", ") { dns.optString(it) })
            }
            Note(o.optString("dnsNote"))
            Note(o.optString("vpnNote"))

            val dm = o.optJSONArray("duplicateMacs")
            if (dm != null) for (i in 0 until dm.length()) {
                val d = dm.optJSONObject(i) ?: continue
                val ips = d.optJSONArray("ips")
                Finding(
                    "One device (MAC ${d.optString("mac")}) is answering for " +
                        "${ips?.length() ?: 0} different IP addresses: " +
                        (0 until (ips?.length() ?: 0)).joinToString(", ") { ips!!.optString(it) } +
                        ". That is the shape ARP poisoning leaves behind — and also what a router " +
                        "that is simultaneously DNS and DHCP server looks like.",
                    Level.WARN,
                )
            }

            if (deep) {
                ThinDivider()
                val devs = o.optJSONArray("devices")
                if (devs == null || devs.length() == 0) Note("No ARP neighbours to list.")
                else for (i in 0 until devs.length()) {
                    val d = devs.optJSONObject(i) ?: continue
                    KeyValue(d.optString("ip"), d.optString("mac") + "  " + d.optString("iface"))
                }
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Check now", probe.busy) { probe.refresh() }
            SecondaryButton(if (deep) "Hide neighbours" else "Show neighbours") { deep = !deep }
        }
        Note(
            "Read-only. The kernel's own ARP table and the OS's own link properties are " +
                "inspected; nothing is sent, injected, probed or redirected. This is the detector " +
                "for LAN interception, not a tool for performing it."
        )
    }
}

// ------------------------------------------------------------------ Tower log

@Composable
private fun TowerCard() {
    val stats = rememberProbe { Sentinel.towers.stats() }
    val act = rememberAction()

    OrbCard {
        val o = stats.json
        val running = o?.optBoolean("running") == true
        CardHeader("Tower + position log", if (running) "logging" else "off",
            if (running) Level.OK else Level.UNKNOWN)

        KeyValue("Fixes stored", o?.optInt("fixes")?.toString() ?: "—")
        KeyValue("Distinct cells", o?.optInt("uniqueCells")?.toString() ?: "—")
        KeyValue("Seen once only", o?.optInt("singletonCells")?.toString() ?: "—")
        KeyValue("Interval", o?.optLong("intervalSec")?.let { "${it}s" } ?: "—")
        KeyValue("Distance trigger", o?.optDouble("distanceM")?.let { "${it.toInt()}m" } ?: "—")
        KeyValue("Accuracy gate", o?.optDouble("accuracyGateM")?.let { "${it.toInt()}m" } ?: "—")

        Note(
            "This log CONTAINS LOCATION and is therefore kept OUT of the encrypted vault — the " +
                "vault is the file most worth stealing and a movement history is the most damaging " +
                "thing it could hold. Nothing is uploaded: there is no server, and Tower " +
                "Collector's OpenCelliD submission is deliberately not ported. It exists for the " +
                "one detection the live cellular checks structurally cannot make — the same cell " +
                "identity logged more than 35km from where it was first seen."
        )

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton(if (running) "Stop logging" else "Start logging", act.busy) {
                act.go {
                    if (Sentinel.towers.isRunning()) { Sentinel.towers.stop(); "stopped" }
                    else { Sentinel.towers.start(); "logging" }
                }
                stats.refresh()
            }
            SecondaryButton("Sample now") {
                act.go { Sentinel.towers.tick() }
                stats.refresh()
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.sm),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            SecondaryButton("Export GPX") {
                act.go { save("chaos-orb-towers.gpx", "application/gpx+xml", Sentinel.towers.exportGpx()) }
            }
            SecondaryButton("Export KML") {
                act.go { save("chaos-orb-towers.kml", "application/vnd.google-earth.kml+xml", Sentinel.towers.exportKml()) }
            }
            SecondaryButton("Export CSV") {
                act.go { save("chaos-orb-towers.csv", "text/csv", Sentinel.towers.exportCsv()) }
            }
        }
        act.result?.let { Note(it) }
    }
}

/**
 * Every export goes through [com.ant.emichaosbg.Exporter], which clears MediaStore's
 * IS_PENDING flag and then QUERIES THE ROW BACK for its real size and real display
 * name. A file that stayed pending or landed empty is reported as a failure rather
 * than a success toast pointing at an empty folder.
 */
private fun save(name: String, mime: String, content: String): String {
    val r = runCatching { JSONObject(Sentinel.exporter.save(name, mime, content)) }.getOrNull()
        ?: return "export failed: no result"
    return if (r.optBoolean("ok"))
        "Saved ${r.optInt("bytes")} bytes to ${r.optString("path")}"
    else "Export FAILED: ${r.optString("reason")}"
}
