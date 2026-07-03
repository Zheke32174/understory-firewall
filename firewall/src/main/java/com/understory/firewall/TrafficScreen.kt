package com.understory.firewall

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.ErrorState
import com.understory.security.ui.components.LoadingState
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Traffic by App (design-v2/firewall.md §5.2). Honest rootless answer to
 * "who talked and how much" — observation, not interception. All five UI
 * states present; never a dead chart. Opt-in behind PACKAGE_USAGE_STATS.
 */
@Composable
fun TrafficScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var window by remember { mutableStateOf(TrafficAccounting.Window.TODAY) }
    var result by remember { mutableStateOf<TrafficAccounting.Result?>(null) }
    var tick by remember { mutableStateOf(0) }

    LaunchedEffect(window, tick) {
        result = null
        result = withContext(Dispatchers.IO) { TrafficAccounting.query(ctx, window) }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_START) tick++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    SuiteScaffold(title = "Traffic by app", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                for (w in TrafficAccounting.Window.values()) {
                    SecureOutlinedButton(onClick = { window = w }) {
                        Text(if (w == window) "• ${w.label}" else w.label)
                    }
                }
            }

            when (val r = result) {
                null -> LoadingState(label = "Reading traffic…")
                is TrafficAccounting.Result.NeedsGrant -> NeedsGrantState()
                is TrafficAccounting.Result.Empty ->
                    EmptyState(title = "No traffic recorded in this window.")
                is TrafficAccounting.Result.Error ->
                    ErrorState(message = r.message, onRetry = { tick++ })
                is TrafficAccounting.Result.Data -> {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        items(r.apps, key = { "t-${it.uid}" }) { app -> TrafficRow(app) }
                        item {
                            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
                            BoundaryText(
                                "This is accounting, not blocking. It shows totals after the " +
                                    "fact and can't see hosts or contents. Restrictions are " +
                                    "applied by Android, not this app."
                            )
                            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun NeedsGrantState() {
    val ctx = LocalContext.current
    SuiteCard {
        Text("Usage access needed", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            "Grant Usage access to see per-app traffic. This stays on your device — we " +
                "send nothing.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureButton(
            onClick = {
                runCatching {
                    ctx.startActivity(
                        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Open Usage access") }
    }
}

@Composable
private fun TrafficRow(app: TrafficAccounting.AppTraffic) {
    val ctx = LocalContext.current
    var expanded by remember { mutableStateOf(false) }
    SuiteCard(onClick = { expanded = !expanded }) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(Modifier) {
                Text(app.label, style = MaterialTheme.typography.bodyLarge)
                if (app.packages.size > 1) {
                    Text(
                        "shared UID: ${app.packages.joinToString(", ")}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Text(
                TrafficAccounting.formatBytes(app.totalBytes),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        if (expanded) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                "Wi-Fi ${TrafficAccounting.formatBytes(app.wifiBytes)} · " +
                    "Cellular ${TrafficAccounting.formatBytes(app.cellBytes)}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SecureOutlinedButton(
                onClick = {
                    val pkg = app.packages.firstOrNull() ?: return@SecureOutlinedButton
                    runCatching {
                        ctx.startActivity(
                            Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:$pkg"),
                            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Restrict this app — Android enforces it") }
        }
    }
}
