package com.ant.emichaosbg.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.ant.emichaosbg.core.Sentinel
import com.ant.emichaosbg.core.SentinelService
import kotlinx.coroutines.delay

/**
 * MASK — the app's second, entirely self-contained function, plus the microphone
 * analysis that shares the audio stack with it.
 *
 * WHAT WAS WRONG BEFORE. `audio/NativeMasker.kt` — a complete, WebView-free
 * AudioTrack synthesis engine — sat in the tree with ZERO references anywhere in
 * the app, while the masker that actually ran was a Web Audio graph inside
 * assets/index.html. To keep that graph alive after the app was swiped away, the
 * service stood up a SECOND WebView, loaded the page into it and
 * evaluateJavascript-clicked the `#go` button. A whole browser instance held up to
 * run an oscillator. This screen is NativeMasker's first caller, and that hack is
 * gone rather than ported.
 */
@Composable
fun MaskScreen(padding: PaddingValues) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
        item { Column { SectionHeader("Masking engine"); MaskerCard() } }
        item { Column { SectionHeader("Microphone"); MicCard() } }
    }
}

// ------------------------------------------------------------------ masker

@Composable
private fun MaskerCard() {
    val ctx = LocalContext.current
    var running by remember { mutableStateOf(Sentinel.masker.isRunning()) }
    var last by remember { mutableStateOf<String?>(null) }

    var level by remember { mutableFloatStateOf(Sentinel.masker.level) }
    var density by remember { mutableFloatStateOf(Sentinel.masker.density) }
    var brightness by remember { mutableFloatStateOf(Sentinel.masker.brightness) }
    var chaos by remember { mutableFloatStateOf(Sentinel.masker.chaosAmt) }
    var sub by remember { mutableFloatStateOf(Sentinel.masker.subLevel) }
    var ultra by remember { mutableFloatStateOf(Sentinel.masker.ultraLevel) }
    var sweep by remember { mutableFloatStateOf(Sentinel.masker.sweepAmt) }
    var comb by remember { mutableFloatStateOf(Sentinel.masker.combAmt) }

    OrbCard {
        CardHeader("Native masking synthesis", if (running) "playing" else "stopped",
            if (running) Level.OK else Level.UNKNOWN)

        KeyValue("Engine", "AudioTrack, 48 kHz stereo, float PCM")
        KeyValue("Thread", "dedicated, MAX_PRIORITY-1")
        KeyValue("Limiter", "k-norm, unit slope at origin")

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton(if (running) "Stop masking" else "Start masking", false) {
                last = if (Sentinel.masker.isRunning()) {
                    Sentinel.stopMasking(); "stopped"
                } else {
                    Sentinel.startMasking()
                }
                running = Sentinel.masker.isRunning()
                SentinelService.syncType(ctx)
            }
        }
        last?.let { Note("Engine: $it") }

        ThinDivider()
        Knob("Level", level) { level = it; Sentinel.masker.level = it }
        Knob("Event density", density) { density = it; Sentinel.masker.density = it }
        Knob("Brightness", brightness) { brightness = it; Sentinel.masker.brightness = it }
        Knob("Chaos", chaos) { chaos = it; Sentinel.masker.chaosAmt = it }
        Knob("Sub rumble", sub) { sub = it; Sentinel.masker.subLevel = it }
        Knob("Wandering spur", sweep) { sweep = it; Sentinel.masker.sweepAmt = it }
        Knob("Switching comb", comb) { comb = it; Sentinel.masker.combAmt = it }
        Knob("Ultrasonic pilots", ultra) { ultra = it; Sentinel.masker.ultraLevel = it }

        Note(
            "Sources actually synthesised: shaped noise floor, wandering spur, arc/impulse " +
                "events, sub rumble, switching comb and — only when the slider above is off zero — " +
                "ultrasonic pilots. Three chaos cores (logistic, Hénon, Lorenz) drive the " +
                "modulation. This is the CORE masking synthesis. The old page engine's 49-source " +
                "set, modulation matrix and BadJack DSP rack are NOT ported, and claiming parity " +
                "would be a lie."
        )
        Note(
            "The output limiter is y = x / (1 + |x|^k)^(1/k): unit slope at the origin, so it " +
                "cannot apply makeup gain, and a ceiling of exactly 1.0. The curve it replaced " +
                "amplified quiet material by up to 3.87x while never actually limiting."
        )
    }
}

@Composable
private fun Knob(label: String, value: Float, onChange: (Float) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.xs),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = OrbTheme.spacing.sm),
        )
        Slider(
            value = value,
            onValueChange = onChange,
            valueRange = 0f..1f,
            modifier = Modifier.weight(1f),
        )
        Text(
            "%.2f".format(value),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(start = OrbTheme.spacing.sm),
        )
    }
}

// ------------------------------------------------------------------ mic

@Composable
private fun MicCard() {
    val ctx = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    val ask = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { ok -> granted = ok }

    val probe = rememberProbe { Sentinel.ultrasonic.snapshot() }
    var last by remember { mutableStateOf<String?>(null) }

    // Live meter while the mic is running: the whole point is watching a band you
    // cannot hear, so a static number would be useless.
    LaunchedEffect(Unit) {
        while (true) {
            delay(1_000)
            if (Sentinel.isInitialised() && Sentinel.mic.isRunning()) probe.refresh()
        }
    }

    OrbCard {
        val o = probe.json
        val micOn = o?.optBoolean("micRunning") == true
        CardHeader("Ultrasonic watch", if (micOn) "listening" else "off",
            if (micOn) Level.OK else Level.UNKNOWN)

        if (!granted) {
            Finding(
                "Microphone permission is not granted, so nothing is being analysed. Grant it " +
                    "below — audio is analysed in the capture loop and the samples are discarded " +
                    "in the same iteration. Nothing is buffered, written to disk, or sent anywhere.",
                Level.WARN,
            )
        }

        KeyValue("Samples", o?.optLong("samples")?.toString() ?: "—")
        KeyValue("18–23 kHz now", o?.optDouble("ultra")?.let { "%.3f".format(it) } ?: "—",
            if ((o?.optDouble("ultra") ?: 0.0) >= (o?.optDouble("threshold") ?: 1.0))
                Level.WARN else Level.OK)
        KeyValue("Speech band now", o?.optDouble("speech")?.let { "%.3f".format(it) } ?: "—")
        KeyValue("Peak seen", o?.optDouble("peak")?.let { "%.3f".format(it) } ?: "—")
        KeyValue("Sustain", "${o?.optInt("streak") ?: 0} / ${o?.optInt("sustainNeeded") ?: 6}")
        KeyValue("Findings raised", o?.optLong("alerts")?.toString() ?: "—")
        o?.optString("micError")?.takeIf { it.isNotBlank() }
            ?.let { KeyValue("Capture error", it, Level.ALERT) }

        LinearProgressIndicator(
            progress = { ((o?.optDouble("ultra") ?: 0.0).toFloat()).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.sm),
        )

        o?.optString("lastFinding")?.takeIf { it.isNotBlank() }
            ?.let { Finding(it, Level.WARN) }

        Row(
            Modifier.fillMaxWidth().padding(top = OrbTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RunButton(if (micOn) "Stop listening" else "Start listening", probe.busy) {
                if (!granted) {
                    ask.launch(Manifest.permission.RECORD_AUDIO)
                } else {
                    last = if (Sentinel.mic.isRunning()) {
                        Sentinel.stopMic(); "stopped"
                    } else {
                        Sentinel.startMic()
                    }
                    SentinelService.syncType(ctx)
                    probe.refresh()
                }
            }
            SecondaryButton("Refresh") { probe.refresh() }
        }
        last?.let { Note("Capture: $it") }

        Note(o?.optString("note") ?: "")
        Note(
            "The capture path searches source x rate — UNPROCESSED, then VOICE_RECOGNITION, then " +
                "MIC, at 48k / 44.1k / 16k — rather than pinning UNPROCESSED and failing on a " +
                "device that does not implement it. UNPROCESSED is preferred because the " +
                "platform's AGC and noise suppression roll off exactly the band this reads."
        )
    }
}
