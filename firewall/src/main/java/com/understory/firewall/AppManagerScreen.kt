package com.understory.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * App Manager — the package-manager half of De1984, absorbed. Lists installed apps
 * (user + system) with enabled/disabled state and, when the privileged backend is
 * granted, offers the rootless package operations De1984 centres on: enable/disable a
 * whole app, force-stop, clear data, and uninstall. Every action goes through the same
 * [Elevation] Shizuku shell the firewall backend already uses — no reflected
 * `Shizuku.newProcess`, and nothing here claims to act without the grant.
 *
 * Superior-variant notes vs the donor: disable uses `pm disable-user` (reversible, works
 * on system apps that a non-root user cannot uninstall), and the destructive actions
 * (clear data, uninstall) are behind an explicit confirm so a mistap can't wipe an app.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AppManagerScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var apps by remember { mutableStateOf<List<ManagedApp>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var filter by remember { mutableStateOf(AppFilter.User) }
    var query by remember { mutableStateOf("") }
    var sheetFor by remember { mutableStateOf<ManagedApp?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    val canManage = remember { Elevation.canManageApps(ctx) }

    suspend fun reload() {
        apps = withContext(Dispatchers.IO) { ManagedApp.loadAll(ctx) }
        loading = false
    }
    LaunchedEffect(Unit) { reload() }

    val filtered = remember(apps, filter, query) {
        val q = query.trim().lowercase()
        apps.asSequence()
            .filter { app ->
                when (filter) {
                    AppFilter.User -> !app.isSystem
                    AppFilter.System -> app.isSystem
                    AppFilter.Disabled -> !app.enabled
                    AppFilter.All -> true
                }
            }
            .filter { q.isEmpty() || it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q) }
            .sortedBy { it.label.lowercase() }
            .toList()
    }

    SuiteScaffold(title = "App Manager", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            if (!canManage) {
                SuiteCard {
                    Text("Read-only", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    BoundaryText(
                        "The privileged backend (Shizuku/Yojimbo) is not granted, so this lists " +
                            "apps and their state but cannot enable/disable, force-stop, clear, or " +
                            "uninstall. Grant it in Elevation to light up the actions.",
                    )
                }
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                label = { Text("Search apps") },
                modifier = Modifier.fillMaxWidth(),
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                AppFilter.entries.forEach { f ->
                    FilterChip(
                        selected = filter == f,
                        onClick = { filter = f },
                        label = { Text(f.label) },
                    )
                }
            }
            status?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            when {
                loading -> Text("Loading installed apps…", style = MaterialTheme.typography.bodyMedium)
                filtered.isEmpty() -> EmptyState(
                    title = if (query.isNotEmpty()) "No matches for \"$query\"."
                    else "Nothing under this filter.",
                )
                else -> LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    items(filtered, key = { "m-${it.packageName}" }) { app ->
                        SuiteListRow(
                            headline = app.label + if (!app.enabled) "  (disabled)" else "",
                            supporting = app.packageName +
                                if (app.isSystem) "  · system" else "",
                            onClick = { sheetFor = app },
                        )
                    }
                    item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
                }
            }
        }
    }

    sheetFor?.let { app ->
        AppActionSheet(
            app = app,
            canManage = canManage,
            onDismiss = { sheetFor = null },
            onResult = { msg ->
                status = msg
                scope.launch { reload() }
            },
        )
    }
}

private enum class AppFilter(val label: String) {
    User("User"), System("System"), Disabled("Disabled"), All("All")
}

/** A managed installed app with the state the manager needs to filter and act. */
data class ManagedApp(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val enabled: Boolean,
) {
    companion object {
        fun loadAll(ctx: Context): List<ManagedApp> {
            val pm = ctx.packageManager
            return runCatching {
                // MATCH_DISABLED_COMPONENTS so disabled apps still appear (that's the point).
                val flags = PackageManager.GET_META_DATA or PackageManager.MATCH_DISABLED_COMPONENTS
                pm.getInstalledApplications(flags)
                    .filter { it.packageName != ctx.packageName }
                    .map { ai ->
                        ManagedApp(
                            packageName = ai.packageName,
                            label = ai.loadLabel(pm).toString(),
                            isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                            enabled = ai.enabled,
                        )
                    }
            }.getOrDefault(emptyList())
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppActionSheet(
    app: ManagedApp,
    canManage: Boolean,
    onDismiss: () -> Unit,
    onResult: (String) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf<ConfirmAction?>(null) }

    fun run(verb: String, block: suspend () -> Outcome) {
        if (busy) return
        busy = true
        scope.launch {
            Diagnostics.log("firewall.AppManager", "$verb: ${app.packageName}")
            val outcome = withContext(Dispatchers.IO) { runCatching { block() }.getOrElse { Outcome.Failed(it.message ?: "error") } }
            val msg = when (outcome) {
                is Outcome.Success -> "$verb: ${app.label} — done"
                is Outcome.Unsupported -> "$verb: needs the privileged backend"
                is Outcome.Failed -> "$verb failed: ${outcome.message}"
            }
            busy = false
            onDismiss()
            onResult(msg)
        }
    }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(app.label, style = MaterialTheme.typography.titleLarge)
            Text(
                app.packageName + (if (app.isSystem) "  · system" else "") +
                    (if (!app.enabled) "  · disabled" else ""),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (!canManage) {
                BoundaryText(
                    "Grant the Shizuku/Yojimbo backend in Elevation to enable these actions.",
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            }

            // Reversible neutralise first, destructive last (behind a confirm).
            if (app.enabled) {
                SecureOutlinedButton(
                    onClick = { run("Disable") { Elevation.setApplicationEnabled(ctx, app.packageName, false) } },
                    enabled = canManage && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Disable app") }
            } else {
                SecureButton(
                    onClick = { run("Enable") { Elevation.setApplicationEnabled(ctx, app.packageName, true) } },
                    enabled = canManage && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Enable app") }
            }
            SecureOutlinedButton(
                onClick = { run("Force-stop") { Elevation.forceStop(ctx, app.packageName) } },
                enabled = canManage && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Force stop") }
            SecureOutlinedButton(
                onClick = { confirm = ConfirmAction.CLEAR },
                enabled = canManage && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Clear data") }
            if (!app.isSystem) {
                SecureOutlinedButton(
                    onClick = { confirm = ConfirmAction.UNINSTALL },
                    enabled = canManage && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Uninstall") }
            } else {
                BoundaryText(
                    "System app: uninstall is unavailable for a non-root user. Disable removes " +
                        "it from the launcher and stops it running, reversibly.",
                )
            }
        }
    }

    confirm?.let { action ->
        val (title, body, verb, op) = when (action) {
            ConfirmAction.CLEAR -> Confirm(
                "Clear ${app.label} data?",
                "Resets the app to first-install state — sign-ins, caches, and local data are wiped. " +
                    "The app stays installed.",
                "Clear data",
            ) { Elevation.clearAppData(ctx, app.packageName) }
            ConfirmAction.UNINSTALL -> Confirm(
                "Uninstall ${app.label}?",
                "Removes the app and its data from this device.",
                "Uninstall",
            ) { Elevation.uninstall(ctx, app.packageName) }
        }
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(title) },
            text = { Text(body) },
            confirmButton = {
                TextButton(onClick = { confirm = null; run(verb, op) }) { Text(verb) }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel") } },
        )
    }
}

private enum class ConfirmAction { CLEAR, UNINSTALL }

private data class Confirm(
    val title: String,
    val body: String,
    val verb: String,
    val op: suspend () -> Outcome,
)
