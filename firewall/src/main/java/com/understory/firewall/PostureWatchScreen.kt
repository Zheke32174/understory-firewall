package com.understory.firewall

import android.Manifest
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Posture Watch (design-v2/firewall.md §5.4, background composition). The opt-in
 * scheduled re-check: turn it on and the app periodically re-runs the SAME
 * rootless posture reads the Overview shows, compares them to the last baseline,
 * and raises one honest notification when something got worse — a new
 * remote-admin grant, Private DNS turned off, or a dropped VPN.
 *
 * Everything here is honest and opt-in:
 *  - The master switch is off until the user flips it; flipping it takes an
 *    immediate baseline and arms an inexact AlarmManager re-check.
 *  - If POST_NOTIFICATIONS isn't granted we say so plainly and offer to request
 *    it — the watch still runs and the in-app "last check" line still updates,
 *    so coverage is never overstated.
 *  - Nothing here blocks traffic; the copy repeats that.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PostureWatchScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var enabled by remember { mutableStateOf(PostureWatch.isEnabled(ctx)) }
    var intervalHours by remember { mutableStateOf(PostureWatch.getIntervalHours(ctx)) }
    var canNotify by remember { mutableStateOf(PostureWatchNotifier.canNotify(ctx)) }
    var lastRun by remember { mutableStateOf(PostureWatch.getLastRunMillis(ctx)) }
    var lastResult by remember { mutableStateOf(PostureWatch.getLastResult(ctx)) }
    var baseline by remember { mutableStateOf(PostureWatch.getBaseline(ctx)) }
    var busy by remember { mutableStateOf(false) }

    fun refresh() {
        enabled = PostureWatch.isEnabled(ctx)
        intervalHours = PostureWatch.getIntervalHours(ctx)
        canNotify = PostureWatchNotifier.canNotify(ctx)
        lastRun = PostureWatch.getLastRunMillis(ctx)
        lastResult = PostureWatch.getLastResult(ctx)
        baseline = PostureWatch.getBaseline(ctx)
    }

    // Re-read on resume — the user may have granted notifications or changed
    // grants in Settings while we were backgrounded.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_START) refresh()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { canNotify = PostureWatchNotifier.canNotify(ctx) }

    fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            // Pre-13: no runtime permission; if notifications are disabled the
            // user toggles them in app-notification settings.
            runCatching {
                ctx.startActivity(
                    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }
        }
    }

    fun setEnabled(on: Boolean) {
        busy = true
        scope.launch {
            withContext(Bg.io) {
                if (on) PostureWatchScheduler.enable(ctx)
                else PostureWatchScheduler.disable(ctx)
            }
            refresh()
            busy = false
        }
    }

    fun setInterval(hours: Int) {
        PostureWatch.setIntervalHours(ctx, hours)
        intervalHours = PostureWatch.getIntervalHours(ctx)
        // Re-arm so the change takes effect from now (only if running).
        if (enabled) {
            scope.launch { withContext(Bg.io) { PostureWatchScheduler.schedule(ctx) } }
        }
    }

    fun checkNow() {
        busy = true
        scope.launch {
            withContext(Bg.io) { PostureWatch.runOnce(ctx) }
            refresh()
            busy = false
        }
    }

    SuiteScaffold(title = "Posture watch", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

            Text(
                "Periodically re-checks your posture in the background and notifies you " +
                    "only when something gets worse — a new app that can control this device, " +
                    "Private DNS turned off, or a dropped VPN. It watches and warns; it never " +
                    "blocks traffic.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // --- Master switch ---
            SuiteCard {
                SwitchRow(
                    label = "Scheduled re-check",
                    checked = enabled,
                    enabled = !busy,
                    onCheckedChange = { setEnabled(it) },
                    supporting = if (enabled)
                        "On — re-checking about every ${intervalLabel(intervalHours)}."
                    else "Off — no background checks run.",
                )
            }

            if (enabled) {
                // --- Notification-permission honesty ---
                if (!canNotify) {
                    Surface(
                        color = UnderstoryTheme.semantic.warningContainer,
                        contentColor = UnderstoryTheme.semantic.warning,
                        shape = MaterialTheme.shapes.medium,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(UnderstoryTheme.spacing.lg)) {
                            Text(
                                "Notifications are off",
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                            Text(
                                "The watch will still run and record each check below, but it " +
                                    "can't alert you until you allow notifications.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                            SecureButton(
                                onClick = { requestNotifications() },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Allow notifications") }
                        }
                    }
                }

                // --- Cadence picker ---
                SuiteSectionHeader("How often")
                SuiteCard {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    ) {
                        for (h in PostureWatch.INTERVAL_CHOICES) {
                            SecureOutlinedButton(onClick = { setInterval(h) }) {
                                Text(if (h == intervalHours) "• ${intervalLabel(h)}" else intervalLabel(h))
                            }
                        }
                    }
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    Text(
                        "Checks are inexact and battery-friendly — Android may run them a " +
                            "little early or late to save power.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                // --- Last check ---
                SuiteSectionHeader("Last check")
                SuiteCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            if (lastRun > 0L) relativeTime(lastRun) else "Not run yet",
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                    if (lastResult != null) {
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        Text(
                            lastResult!!,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    SecureOutlinedButton(
                        onClick = { checkNow() },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(if (busy) "Checking…" else "Check now") }
                }

                // --- Current baseline (what the next check compares against) ---
                SuiteSectionHeader("What's being watched")
                BaselineCard(baseline)
            }

            BoundaryText(
                "This is a read-and-warn tool. It uses only the same on-device reads the " +
                    "dashboard shows, records nothing but package names, and sends nothing off " +
                    "your device."
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

@Composable
private fun BaselineCard(baseline: PostureWatch.PostureSnapshot?) {
    SuiteCard {
        if (baseline == null) {
            Text(
                "No baseline yet",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                "The first check records a baseline. After that, only changes from it are " +
                    "flagged.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@SuiteCard
        }

        // VPN + DNS snapshot lines.
        val vpnLine = when (baseline.aVpnIsUp) {
            Tri.YES -> "A VPN is up"
            Tri.NO -> "No VPN is up"
            Tri.UNKNOWN -> "VPN state unknown"
        }
        val dnsLine = when (baseline.dnsMode) {
            "hostname" -> "Private DNS: encrypted (DoT)"
            "off" -> "Private DNS: off (unencrypted)"
            else -> "Private DNS: opportunistic"
        }
        Text(vpnLine, style = MaterialTheme.typography.bodyLarge)
        Text(
            dnsLine,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        val holders = baseline.capHolders
        if (holders.isEmpty()) {
            Text(
                "No apps currently hold remote-admin-class grants.",
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.success,
            )
        } else {
            Text(
                "${holders.size} remote-admin grant(s) on record:",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            // Group by app so an app with two caps reads as one line.
            for ((label, caps) in holders.groupBy { it.label }
                .mapValues { (_, v) -> v.map { it.capability.display } }
                .toList()
                .sortedBy { it.first.lowercase() }) {
                Text(
                    "•  $label — ${caps.distinct().joinToString(", ")}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = UnderstoryTheme.spacing.xs),
                )
            }
        }
    }
}

/** "6 hours" / "1 day" / "3 days" for an hour count. */
private fun intervalLabel(hours: Int): String = when {
    hours < 24 -> "$hours hours"
    hours == 24 -> "1 day"
    else -> "${hours / 24} days"
}

/** Coarse relative-time label for the last-run stamp. No seconds precision. */
private fun relativeTime(millis: Long): String {
    val delta = System.currentTimeMillis() - millis
    if (delta < 0) return "just now"
    val mins = delta / 60000L
    return when {
        mins < 1 -> "just now"
        mins < 60 -> "$mins min ago"
        mins < 60 * 24 -> "${mins / 60} h ago"
        else -> "${mins / (60 * 24)} d ago"
    }
}
