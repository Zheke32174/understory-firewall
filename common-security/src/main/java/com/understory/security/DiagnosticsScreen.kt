package com.understory.security

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.delay

/**
 * In-app debugger surface. Scrollable list of recent diagnostic events
 * plus Copy and Clear actions. Refreshes itself every second so a tap
 * sequence the user just performed shows up without leaving the screen.
 *
 * Intended use: each app exposes a small "Diagnostics" link on its
 * main screen. User taps, navigates to this screen, performs the
 * action that's failing in another tab/screen of the same app, comes
 * back to Diagnostics, sees what fired (or didn't). Tap Copy to put
 * the full dump on the clipboard for pasting back to chat.
 */
@Composable
fun DiagnosticsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var events by remember { mutableStateOf(Diagnostics.snapshot()) }

    // Refresh once per second so events from other screens / lifecycle
    // hooks appear without leaving this screen. Cheap — list is bounded.
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000L)
            events = Diagnostics.snapshot()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("diagnostics", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Live event ring (${events.size}). Reproduce the bug, come back, " +
                "tap Copy, paste to chat.",
            color = Color(0xFF9E9E9E), fontSize = 11.sp,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val text = Diagnostics.formatForExport()
                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    cm?.setPrimaryClip(ClipData.newPlainText("understory-diagnostics", text))
                    Toast.makeText(ctx, "Diagnostics copied", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.weight(1f),
            ) { Text("Copy") }
            OutlinedButton(
                onClick = { Diagnostics.clear(); events = Diagnostics.snapshot() },
                modifier = Modifier.weight(1f),
            ) { Text("Clear") }
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f),
            ) { Text("Back") }
        }
        if (events.isEmpty()) {
            Spacer(Modifier.height(20.dp))
            Text("No events yet.", color = Color(0xFF9E9E9E), fontSize = 12.sp)
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                items(events.reversed(), key = { "${it.elapsedMs}-${it.tag}-${it.message.hashCode()}" }) { ev ->
                    EventRow(ev)
                }
            }
        }
    }
}

private val tsFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

@Composable
private fun EventRow(event: Diagnostics.Event) {
    val accent = when (event.level) {
        Diagnostics.Level.INFO -> Color(0xFF9E9E9E)
        Diagnostics.Level.WARN -> Color(0xFFFFB74D)
        Diagnostics.Level.ERROR -> Color(0xFFEF5350)
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(accent.copy(alpha = 0.06f), RoundedCornerShape(4.dp))
            .padding(6.dp),
    ) {
        Column {
            Row {
                Text(
                    tsFormat.format(Date(event.timestampMs)),
                    color = Color(0xFF707070), fontSize = 10.sp,
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    event.tag,
                    color = accent, fontSize = 10.sp,
                )
            }
            Text(event.message, color = Color(0xFFE0E0E0), fontSize = 11.sp)
        }
    }
}
