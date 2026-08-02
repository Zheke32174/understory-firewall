package com.ant.emichaosbg.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.ant.emichaosbg.LogContext
import com.ant.emichaosbg.core.Sentinel
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * VAULT — every finding this app has ever recorded, and whether the record can
 * still be trusted.
 *
 * The store is AES-256-GCM under a non-exportable Keystore key (StrongBox when the
 * device has one), each record's sequence number bound in as GCM associated data,
 * a SHA-256 hash chain across records, and a separately sealed head holding the
 * count and chain value so TRUNCATION is detectable — a shortened chain still
 * verifies on its own, which is why the head exists.
 *
 * THERE IS NO DELETE, NO CLEAR AND NO TRUNCATE. Not a guarded one, not an internal
 * one. A log the app can empty is not evidence. The only removal path in the class
 * is size-driven rotation, and rotation KEEPS the rotated segment.
 */
@Composable
fun VaultScreen(padding: PaddingValues) {
    var limit by remember { mutableIntStateOf(60) }
    val entries = rememberProbe { Sentinel.vault.read(limit) }
    val verify = rememberProbe(autoRun = false) { Sentinel.vault.verify() }
    val act = rememberAction()

    LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
        item {
            SectionHeader("Integrity")
            OrbCard {
                val e = entries.json
                val v = verify.json
                val readable = e?.optLong("readable") ?: -1
                val head = e?.optLong("headCount") ?: -1
                CardHeader(
                    "Encrypted, append-only, hash-chained",
                    when {
                        v == null -> "not verified"
                        v.optBoolean("ok") -> "verified"
                        else -> "check failed"
                    },
                    when {
                        v == null -> Level.UNKNOWN
                        v.optBoolean("ok") -> Level.OK
                        else -> Level.ALERT
                    },
                )
                KeyValue("Records (head)", if (head >= 0) head.toString() else "—")
                KeyValue("Records readable", if (readable >= 0) readable.toString() else "—",
                    if (readable in 0..<head) Level.WARN else Level.OK)
                if (v != null) {
                    KeyValue("Chain intact", if (v.optBoolean("chainIntact")) "yes" else "NO",
                        if (v.optBoolean("chainIntact")) Level.OK else Level.ALERT)
                    KeyValue("Head matches", if (v.optBoolean("headMatches")) "yes" else "NO",
                        if (v.optBoolean("headMatches")) Level.OK else Level.ALERT)
                    KeyValue("StrongBox", if (v.optBoolean("strongBox")) "yes" else "no")
                    if (v.has("firstBadSeq")) KeyValue("First bad record",
                        v.optLong("firstBadSeq").toString(), Level.ALERT)
                    v.optString("note").takeIf { it.isNotBlank() }?.let { Finding(it, Level.WARN) }
                    v.optString("lastError").takeIf { it.isNotBlank() }
                        ?.let { Finding(it, Level.WARN) }
                }
                if (e?.optBoolean("truncated") == true) {
                    Finding(
                        e.optString("note").ifBlank {
                            "The head counts more records than could be read."
                        },
                        Level.ALERT,
                    )
                    e.optString("stoppedBecause").takeIf { it.isNotBlank() }
                        ?.let { Finding("Reading stopped: $it", Level.ALERT) }
                }
                Note(
                    "\"Nothing was ever recorded\" and \"the log would not open\" are different " +
                        "claims and are rendered differently. The head count is O(1); the readable " +
                        "count is a full walk with a decrypt per record, and any divergence " +
                        "between the two is shown above rather than hidden."
                )
                Row(
                    Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    RunButton("Verify chain", verify.busy) { verify.refresh() }
                    SecondaryButton("Reload") { entries.refresh() }
                }
            }
        }

        item {
            SectionHeader("Export")
            OrbCard {
                Note(
                    "Exports go to public Downloads through MediaStore. The write is VERIFIED — " +
                        "the pending flag is cleared and the row is queried back for its real size " +
                        "and real display name, so a file that stayed hidden or landed empty is " +
                        "reported as a failure instead of a success toast pointing at an empty " +
                        "folder."
                )
                Row(
                    Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    SecondaryButton("Save JSON") {
                        act.go {
                            report(Sentinel.exporter.save(
                                "chaos-orb-vault.json", "application/json",
                                Sentinel.vault.exportJson()))
                        }
                    }
                    SecondaryButton("Save CSV") {
                        act.go {
                            report(Sentinel.exporter.save(
                                "chaos-orb-vault.csv", "text/csv", Sentinel.vault.exportCsv()))
                        }
                    }
                    SecondaryButton("Share JSON") {
                        act.go {
                            report(Sentinel.exporter.share(
                                "chaos-orb-vault.json", "application/json",
                                Sentinel.vault.exportJson()))
                        }
                    }
                }
                act.result?.let { Note(it) }
            }
        }

        item { SectionHeader("Findings, newest first") }

        val list = entries.json?.optJSONArray("entries")
        if (list == null || list.length() == 0) {
            item {
                OrbCard {
                    CardHeader("Nothing recorded yet", "empty", Level.UNKNOWN)
                    Note(
                        if (entries.json?.optBoolean("truncated") == true)
                            "This is NOT an empty log — see the integrity card above."
                        else
                            "No detector has raised a finding yet. Every finding raised by every " +
                                "detector in this app lands here, whether or not a screen was open " +
                                "at the time."
                    )
                }
            }
        } else {
            items@ for (i in 0 until list.length()) {
                val rec = list.optJSONObject(i) ?: continue@items
                item { VaultRow(rec) }
            }
            if (list.length() >= limit) {
                item {
                    OrbCard {
                        SecondaryButton("Load ${limit} more") {
                            limit += 60; entries.refresh()
                        }
                    }
                }
            }
        }
    }
}

private val STAMP = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

@Composable
private fun VaultRow(rec: JSONObject) {
    val sev = rec.optInt("sev")
    OrbCard {
        CardHeader(
            rec.optString("badge").ifBlank { "finding" },
            "#" + rec.optLong("seq"),
            levelOfSeverity(sev),
        )
        KeyValue("When", STAMP.format(Date(rec.optLong("t"))))
        KeyValue("Source", rec.optString("src"))
        val ctxLine = LogContext.summarise(rec.optJSONObject("ctx"))
        if (ctxLine.isNotBlank()) KeyValue("Context", ctxLine)
        Finding(rec.optString("msg"), levelOfSeverity(sev))
    }
}

private fun report(raw: String): String {
    val r = runCatching { JSONObject(raw) }.getOrNull() ?: return "export failed: no result"
    return if (r.optBoolean("ok"))
        "OK — ${r.optString("path")}" +
            (if (r.has("bytes")) " (${r.optInt("bytes")} bytes)" else "")
    else "FAILED — ${r.optString("reason")}"
}
