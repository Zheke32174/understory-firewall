package com.understory.firewall

import android.content.Context
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
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.security.Diagnostics
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Restrict Worklist (design-v2/firewall.md §5.5). The old blocklist UI
 * becomes an "apps to restrict" worklist over the kept AppListLoader
 * substrate. Row tap opens an AppDetailSheet of OS-enforced deep-links,
 * each resolveActivity-guarded so no dead button ships. No control here
 * claims the app itself restricts anything — Android enforces it.
 *
 * Hand-off IN: a flagged package can arrive as an intent extra
 * ([EXTRA_FLAG_PACKAGE]) from antivirus (APK_AUDITOR); we add it to the
 * watched set so it surfaces here.
 */
@Composable
fun RestrictScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var watched by remember { mutableStateOf(FirewallSettings.getRestrictedPackages(ctx)) }
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(RestrictFilter.Watched) }
    var sheetFor by remember { mutableStateOf<AppEntry?>(null) }

    LaunchedEffect(Unit) {
        // Hand-off IN sink: pick up a flagged package if the activity was
        // launched with one (contract owned by the suite doc; we accept it).
        (ctx as? android.app.Activity)?.intent?.getStringExtra(EXTRA_FLAG_PACKAGE)
            ?.takeIf { it.isNotBlank() }?.let { pkg ->
                FirewallSettings.setRestricted(ctx, pkg, true)
            }
        apps = withContext(Dispatchers.IO) { AppListLoader.load(ctx) }
        watched = FirewallSettings.getRestrictedPackages(ctx)
    }

    val filtered = remember(apps, query, watched, filter) {
        val installed = apps.mapTo(HashSet(apps.size)) { it.packageName }
        val stale = (watched - installed).map {
            AppEntry(packageName = it, label = it, isSystemApp = false, isStale = true)
        }
        val effective = apps + stale
        val byFilter = when (filter) {
            RestrictFilter.Watched -> effective.filter { it.packageName in watched }
            RestrictFilter.All -> effective
            RestrictFilter.System -> effective.filter { it.isSystemApp && !it.isStale }
        }
        val q = query.trim().lowercase()
        val matched = if (q.isEmpty()) byFilter else byFilter.filter {
            it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
        }
        matched.sortedWith(
            compareByDescending<AppEntry> { it.packageName in watched }
                .thenBy { it.label.lowercase() }
        )
    }

    SuiteScaffold(title = "Restrict worklist", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            BoundaryText(
                "Restrict via Android — this app opens the setting; Android enforces it. " +
                    "Star an app to keep it on your worklist."
            )
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                for (f in RestrictFilter.values()) {
                    SecureOutlinedButton(onClick = { filter = f }) {
                        Text(if (f == filter) "• ${f.label}" else f.label)
                    }
                }
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search apps") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (apps.isEmpty()) {
                Text("Loading installed apps…", style = MaterialTheme.typography.bodyMedium)
            } else if (filtered.isEmpty()) {
                EmptyState(
                    title = when {
                        filter == RestrictFilter.Watched && query.isEmpty() ->
                            "No apps on your worklist yet."
                        query.isNotEmpty() -> "No matches for \"$query\"."
                        else -> "Nothing here under this filter."
                    },
                    body = if (filter == RestrictFilter.Watched)
                        "Switch to All apps and star the ones you want to keep an eye on."
                    else null,
                )
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    items(filtered, key = { "r-${it.packageName}" }) { entry ->
                        val isWatched = entry.packageName in watched
                        SuiteListRow(
                            headline = entry.label + if (entry.isStale) "  (uninstalled)" else "",
                            supporting = entry.packageName,
                            trailing = {
                                SecureOutlinedButton(onClick = {
                                    FirewallSettings.setRestricted(ctx, entry.packageName, !isWatched)
                                    watched = FirewallSettings.getRestrictedPackages(ctx)
                                }) { Text(if (isWatched) "★" else "☆") }
                            },
                            onClick = { sheetFor = entry },
                        )
                    }
                    item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
                }
            }
        }
    }

    sheetFor?.let { entry ->
        AppDetailSheet(entry = entry, onDismiss = { sheetFor = null })
    }
}

private enum class RestrictFilter(val label: String) {
    Watched("Watched"), All("All apps"), System("System")
}

/** Intent extra carrying a flagged package for the hand-off-IN sink. */
const val EXTRA_FLAG_PACKAGE = "com.understory.firewall.EXTRA_FLAG_PACKAGE"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppDetailSheet(entry: AppEntry, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(entry.label, style = MaterialTheme.typography.titleLarge)
            Text(entry.packageName, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)

            // OPTIONAL-ELEVATION real enforcement (Shizuku netpolicy / pm, or
            // Dhizuku DPM). Only lit up when the capability is actually granted;
            // a stale package (uninstalled) has no live target so we skip it.
            // Rootless users never see these — they get the OS deep-links below,
            // never a dead button.
            if (!entry.isStale) {
                ElevatedRestrictControls(pkg = entry.packageName)
            }

            BoundaryText("Understory opens the setting; Android enforces it.")

            val actions = restrictActions(ctx, entry.packageName)
            for (a in actions) {
                SecureOutlinedButton(
                    onClick = { runCatching { ctx.startActivity(a.intent) } },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(a.label) }
            }
            if (actions.isEmpty()) {
                Text(
                    "No OS controls resolve for this app on this device.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
        }
    }
}

/**
 * The real, elevated per-app enforcement controls. Capability-gated, NOT
 * tier-gated (design principle): we ask "can I block this app's network?" and
 * "can I manage apps?" rather than "is Shizuku present?". When neither
 * capability is granted this composable renders nothing and the caller's OS
 * deep-links remain the honest path — no dead/disabled buttons ship.
 *
 * "Block background data" is labelled honestly: it restricts the app's metered
 * background network (Shizuku `cmd netpolicy … restrict-background-blacklist`);
 * foreground traffic stays reachable unless the app is also suspended. On
 * Dhizuku the broker reports [Outcome.Unsupported] (Device Owner has no per-app
 * metered API); we surface that reason instead of pretending it worked.
 */
@Composable
private fun ElevatedRestrictControls(pkg: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // Capability snapshot — cheap, synchronous predicate reads on the granted
    // tier. Re-read on recomposition so a grant made elsewhere lights these up.
    val canNet = remember(pkg) { Elevation.canControlAppNetwork(ctx) }
    val canManage = remember(pkg) { Elevation.canManageApps(ctx) }
    if (!canNet && !canManage) return

    var status by remember(pkg) { mutableStateOf<String?>(null) }
    var busy by remember(pkg) { mutableStateOf(false) }

    fun render(o: Outcome): String = when (o) {
        is Outcome.Success -> o.detail?.let { "Done — $it" } ?: "Done."
        is Outcome.Unsupported -> "Not available: ${o.reason}"
        is Outcome.Failed -> "Failed: ${o.message}"
    }

    Text(
        "Enforce (elevation on)",
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
    )

    if (canNet) {
        Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
            SecureButton(
                onClick = {
                    if (busy) return@SecureButton
                    busy = true
                    scope.launch {
                        Diagnostics.log("firewall.Restrict", "block bg net: $pkg")
                        val o = Elevation.setAppBackgroundNetworkBlocked(ctx, pkg, blocked = true)
                        status = render(o)
                        busy = false
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text("Block background data") }
            SecureOutlinedButton(
                onClick = {
                    if (busy) return@SecureOutlinedButton
                    busy = true
                    scope.launch {
                        val o = Elevation.setAppBackgroundNetworkBlocked(ctx, pkg, blocked = false)
                        status = render(o)
                        busy = false
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text("Allow") }
        }
        BoundaryText(
            "Blocks metered background data for this app. Foreground use stays " +
                "reachable unless you also suspend it."
        )
    }

    if (canManage) {
        Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
            SecureButton(
                onClick = {
                    if (busy) return@SecureButton
                    busy = true
                    scope.launch {
                        Diagnostics.log("firewall.Restrict", "suspend: $pkg")
                        val o = Elevation.setAppSuspended(ctx, pkg, suspended = true)
                        status = render(o)
                        busy = false
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text("Suspend app") }
            SecureOutlinedButton(
                onClick = {
                    if (busy) return@SecureOutlinedButton
                    busy = true
                    scope.launch {
                        val o = Elevation.setAppSuspended(ctx, pkg, suspended = false)
                        status = render(o)
                        busy = false
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text("Unsuspend") }
        }
        BoundaryText("Suspending greys the app out and stops it launching.")
    }

    status?.let {
        Text(it, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
}

private data class RestrictAction(val label: String, val intent: Intent)

/** Build the resolveActivity-guarded deep-link set for [pkg] (§5.5 table).
 *  Only actions whose target resolves on this device are returned. */
private fun restrictActions(ctx: Context, pkg: String): List<RestrictAction> {
    val pm = ctx.packageManager
    val out = mutableListOf<RestrictAction>()
    fun add(label: String, intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (intent.resolveActivity(pm) != null) out += RestrictAction(label, intent)
    }

    add(
        "App details & permissions",
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")),
    )
    // One UI-specific background-data restriction, if it resolves.
    runCatching {
        add(
            "Restrict background data",
            Intent("android.settings.IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS",
                Uri.parse("package:$pkg")),
        )
    }
    add("Data-saver (global)", Intent(Settings.ACTION_DATA_USAGE_SETTINGS))
    add("Uninstall", Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    return out
}
