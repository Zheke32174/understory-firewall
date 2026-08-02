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
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.ant.emichaosbg.core.Sentinel
import org.json.JSONObject

/**
 * DEVICE — the three detectors that look at this phone and this process rather
 * than at a radio.
 */
@Composable
fun DeviceScreen(padding: PaddingValues) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
        item { Column { SectionHeader("Process integrity"); ProcessCard() } }
        item { Column { SectionHeader("App integrity"); AppIntegrityCard() } }
        item { Column { SectionHeader("Overlays & accessibility"); OverlayCard() } }
    }
}

// ------------------------------------------------------------------ escalation

@Composable
private fun ProcessCard() {
    val probe = rememberProbe { Sentinel.escalation.cached() }

    OrbCard {
        val o = probe.json
        val ran = o?.optBoolean("ran") == true
        val n = o?.optInt("count") ?: 0
        CardHeader(
            "Injection & sandbox",
            when {
                !ran -> "not run"
                n == 0 -> "clean"
                else -> "$n finding${if (n == 1) "" else "s"}"
            },
            when {
                !ran -> Level.UNKNOWN
                n == 0 -> Level.OK
                else -> Level.ALERT
            },
        )

        if (!ran) {
            Note(
                o?.optString("note")
                    ?: "This check has not run yet. That is NOT an all-clear — nothing has been " +
                    "looked at."
            )
        } else {
            KeyValue("TracerPid", o!!.optInt("tracerPid").toString(),
                if (o.optInt("tracerPid") > 0) Level.ALERT else Level.OK)
            KeyValue("Mapped regions", o.optInt("mapCount").toString())
            KeyValue("Writable+exec", o.optInt("wxRegions").toString(),
                if (o.optInt("wxRegions") > 0) Level.WARN else Level.OK)
            KeyValue("Fileless exec", o.optInt("fileless").toString(),
                if (o.optInt("fileless") > 0) Level.ALERT else Level.OK)
            KeyValue("SELinux", o.optString("selinux"),
                if (o.optString("selinux") == "permissive") Level.ALERT else Level.OK)
            KeyValue("Context", o.optString("selinuxContext").ifBlank { "not readable" })
            KeyValue("APK path", o.optString("sourceDir"))
            KeyValue("APK writable", if (o.optBoolean("apkWritable")) "YES" else "no",
                if (o.optBoolean("apkWritable")) Level.ALERT else Level.OK)
            KeyValue("Overlay mounts", o.optInt("suspiciousMounts").toString())

            val hooks = o.optJSONArray("hookFrameworks")
            if (hooks != null && hooks.length() > 0) {
                KeyValue("Hook frameworks",
                    (0 until hooks.length()).joinToString(", ") { hooks.optString(it) }, Level.ALERT)
            }

            val f = o.optJSONArray("findings")
            if (f == null || f.length() == 0) {
                Note(
                    "No tracer attached, no writable-executable pages, no fileless code, no " +
                        "library loaded from a shell-owned directory and no injection framework " +
                        "mapped into this process."
                )
            } else for (i in 0 until f.length()) {
                val x = f.optJSONObject(i) ?: continue
                Finding(x.optString("what"), levelOfSeverity(x.optInt("sev")))
            }
            Note(o.optString("note"))
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Scan now", probe.busy) { probe.refresh() }
        }
    }
}

// ------------------------------------------------------------------ app integrity

@Composable
private fun AppIntegrityCard() {
    val probe = rememberProbe { Sentinel.integrity.status() }

    OrbCard {
        val o = probe.json
        val ran = o?.optBoolean("ran") == true
        val pinned = o?.optBoolean("signaturePinned") == true
        val sigOk = o?.optBoolean("signatureOk") == true
        val n = o?.optInt("count") ?: 0
        CardHeader(
            "Signing certificate & instrumentation",
            when {
                !ran -> "checking"
                !pinned -> "not pinned"
                n == 0 && sigOk -> "verified"
                else -> "$n finding${if (n == 1) "" else "s"}"
            },
            when {
                !ran -> Level.UNKNOWN
                !pinned -> Level.WARN
                n == 0 && sigOk -> Level.OK
                else -> Level.ALERT
            },
        )

        if (!ran) {
            Note("The first integrity scan is still running. This is not a verdict.")
        } else {
            KeyValue("Cert SHA-256", o!!.optString("signatureHash").ifBlank { "unreadable" },
                if (sigOk) Level.OK else Level.ALERT)
            KeyValue("Pinned", if (pinned) "yes" else "NO", if (pinned) Level.OK else Level.WARN)
            KeyValue("Debugger", if (o.optBoolean("debuggerAttached")) "ATTACHED" else "none",
                if (o.optBoolean("debuggerAttached")) Level.ALERT else Level.OK)
            Note(o.optString("signatureNote"))

            val inst = o.optJSONArray("instrumentation")
            if (inst != null && inst.length() > 0) {
                for (i in 0 until inst.length()) Finding(inst.optString(i), Level.ALERT)
            } else {
                Note("No instrumentation agent thread or library is present in this process.")
            }

            val root = o.optJSONArray("root")
            if (root != null && root.length() > 0) {
                ThinDivider()
                KeyValue("Device root", "indicators present", Level.INFO)
                for (i in 0 until root.length()) Finding(root.optString(i), Level.INFO)
                Note(
                    "Root is listed separately from findings on purpose: a rooted phone is the " +
                        "owner controlling their own device, not an attack. This app never " +
                        "refuses to run on one."
                )
            }

            ThinDivider()
            val limits = o.optJSONArray("limits")
            if (limits != null) for (i in 0 until limits.length()) {
                Finding(limits.optString(i), Level.INFO)
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Re-check", probe.busy) { probe.refresh() }
        }
    }
}

// ------------------------------------------------------------------ overlays

@Composable
private fun OverlayCard() {
    val probe = rememberProbe { Sentinel.overlays.status() }
    val act = rememberAction()

    OrbCard {
        val o = probe.json
        val overlays = o?.optInt("overlayCount") ?: 0
        val a11y = o?.optInt("a11yCount") ?: 0
        CardHeader(
            "Who can draw over you, and who can read you",
            if (o == null) "not run" else "$overlays / $a11y",
            when {
                o == null -> Level.UNKNOWN
                a11y > 0 -> Level.WARN
                overlays > 0 -> Level.INFO
                else -> Level.OK
            },
        )

        if (o == null) {
            Note("Not run yet.")
        } else {
            val live = o.optJSONObject("liveWatch")
            val watchOn = live?.optBoolean("enabled") == true
            KeyValue("Live overlay watch", if (watchOn) "enabled" else "off",
                if (watchOn) Level.OK else Level.UNKNOWN)
            if (watchOn) KeyValue("Overlays right now", live!!.optInt("overlays").toString())
            else Note(
                "Live detection of an overlay drawn over this app RIGHT NOW is only possible " +
                    "through an accessibility service, and this one is off. It is opt-in " +
                    "deliberately: an accessibility service is the most powerful thing an app on " +
                    "Android can hold, and this is a tool that warns about exactly that " +
                    "capability. Ours reads window type, layer and bounds only — there is no " +
                    "getRootInActiveWindow() and no node traversal anywhere in it. The list below " +
                    "works without it."
            )

            ThinDivider()
            KeyValue("Can draw on top", overlays.toString())
            if (o.optBoolean("overlayReadable", true)) {
                val apps = o.optJSONArray("overlayApps")
                if (apps == null || apps.length() == 0) {
                    Note("No app currently holds a granted appear-on-top permission.")
                } else for (i in 0 until apps.length()) {
                    val a = apps.optJSONObject(i) ?: continue
                    KeyValue(
                        a.optString("label"),
                        a.optString("pkg") + if (a.optBoolean("system")) "  [system]" else "",
                    )
                }
            } else {
                Note("The installed-package list could not be read, so this list is INCOMPLETE.")
            }

            ThinDivider()
            KeyValue("Accessibility services", a11y.toString(),
                if (a11y > 0) Level.WARN else Level.OK)
            val svcs = o.optJSONArray("a11yServices")
            if (svcs == null || svcs.length() == 0) {
                Note("No accessibility service is enabled on this device.")
            } else for (i in 0 until svcs.length()) {
                val s = svcs.optJSONObject(i) ?: continue
                KeyValue(
                    s.optString("label") + if (s.optBoolean("isThisApp")) " (this app)" else "",
                    s.optString("component"),
                    if (s.optBoolean("isThisApp")) Level.INFO else Level.WARN,
                )
            }
            Note(
                "An accessibility service can read the content of every screen and inject " +
                    "gestures. It is the usual home of stalkerware. Holding the appear-on-top " +
                    "permission is not itself wrongdoing — screen recorders, chat bubbles and " +
                    "colour filters all use it — but it is the capability tapjacking needs."
            )
        }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton("Re-read", probe.busy) { probe.refresh() }
            SecondaryButton("Appear-on-top settings") {
                act.go { if (Sentinel.overlays.openOverlaySettings()) "opened" else "could not open" }
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.sm),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            SecondaryButton("Accessibility settings") {
                act.go {
                    if (Sentinel.overlays.openAccessibilitySettings()) "opened" else "could not open"
                }
            }
        }
        act.result?.let { Note(it) }
    }
}
