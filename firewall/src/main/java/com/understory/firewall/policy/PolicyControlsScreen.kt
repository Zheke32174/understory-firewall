package com.understory.firewall.policy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import com.understory.firewall.AppEntry
import com.understory.firewall.AppListLoader
import com.understory.firewall.BoundaryText
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Stage-3 policy controls (design-v2/firewall.md §7, Stage-3): the global
 * default-policy toggle, per-app screen-off / background flags, named profiles,
 * and the Quick-Settings-tile affordance. All roads lead through
 * [BackendManager], which re-asserts the [UidExemptions] gate on every apply —
 * so BLOCK_ALL / lockdown / a restored profile can NEVER sever Tailscale.
 *
 * HONESTY, kept visible on this screen:
 *   - This is POLICY (may an app reach the network), all-networks, not a routing
 *     tunnel and not per-network granular.
 *   - Rootless firewalls have no true boot persistence — rules are inactive
 *     after a reboot until Shizuku reconnects; the boot receiver re-applies then.
 *   - "Block in background" is approximated by screen-off (no per-app foreground
 *     signal without heavier permission).
 *
 * Degrades to the Elevation explainer when no Shizuku shell tier is granted.
 */
@Composable
fun PolicyControlsScreen(
    onBack: () -> Unit,
    onOpenElevation: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val manager = remember { BackendManager.get(ctx) }

    var available by remember { mutableStateOf(manager.isAvailable()) }
    var tierLabel by remember { mutableStateOf(manager.tierLabel()) }
    var lockdown by remember { mutableStateOf(manager.isLockdown()) }
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var exempt by remember { mutableStateOf<Set<String>>(emptySet()) }
    var screenOff by remember { mutableStateOf(PolicyStore.getScreenOffPackages(ctx)) }
    var background by remember { mutableStateOf(PolicyStore.getBackgroundPackages(ctx)) }
    var profiles by remember { mutableStateOf(PolicyStore.getProfiles(ctx)) }
    var query by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var showSaveDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        available = manager.isAvailable()
        tierLabel = manager.tierLabel()
        lockdown = manager.isLockdown()
        apps = withContext(Dispatchers.IO) { AppListLoader.load(ctx) }
        exempt = withContext(Dispatchers.IO) { UidExemptions.exemptPackages(ctx) }
        screenOff = PolicyStore.getScreenOffPackages(ctx)
        background = PolicyStore.getBackgroundPackages(ctx)
        profiles = PolicyStore.getProfiles(ctx)
    }

    val installedPkgs = remember(apps) { apps.map { it.packageName }.toSet() }

    val filtered = remember(apps, query) {
        val q = query.trim().lowercase()
        val base = if (q.isEmpty()) apps else apps.filter {
            it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
        }
        base.sortedBy { it.label.lowercase() }
    }

    SuiteScaffold(title = "Firewall policy", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

            if (!available) {
                SuiteCard {
                    Text(
                        "Needs Shizuku",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    Text(
                        "Default policy, lockdown, screen-off rules and profiles all " +
                            "enforce through the Shizuku shell (uid 2000). Grant Shizuku " +
                            "to turn them on. Nothing here uses the VPN slot.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    SecureButton(onClick = onOpenElevation, modifier = Modifier.fillMaxWidth()) {
                        Text("Open Elevation")
                    }
                }
                return@Column
            }

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                modifier = Modifier.fillMaxWidth(),
            ) {
                // --- Default policy / lockdown ---
                item {
                    SuiteCard {
                        Text(
                            "Default policy",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        Text(
                            tierLabel,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                        SwitchRow(
                            label = "Lockdown (block all)",
                            supporting = if (lockdown) {
                                "Whitelist mode: every non-exempt app is blocked. Tailscale " +
                                    "and system apps stay exempt."
                            } else {
                                "Blacklist mode: apps reach the network unless you block them " +
                                    "individually. Turn on to block everything except exemptions."
                            },
                            checked = lockdown,
                            enabled = !busy,
                            onCheckedChange = { want ->
                                if (busy) return@SwitchRow
                                busy = true
                                scope.launch {
                                    val r = if (want) manager.applyLockdown(installedPkgs)
                                    else manager.liftLockdown(installedPkgs)
                                    lockdown = manager.isLockdown()
                                    status = (if (want) "Lockdown on" else "Lockdown off") +
                                        ": ${r.changed} changed" +
                                        if (r.failed > 0) ", ${r.failed} failed" else ""
                                    busy = false
                                }
                            },
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        BoundaryText(
                            "Add a \"Lockdown\" tile from your Quick Settings edit panel to " +
                                "toggle this from anywhere. After a reboot rules are inactive " +
                                "until Shizuku reconnects, then re-applied automatically."
                        )
                    }
                }

                status?.let {
                    item {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                // --- Profiles ---
                item {
                    SuiteCard {
                        Text(
                            "Profiles",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        Text(
                            "Save the current policy (default mode + blocked/allowed apps + " +
                                "screen-off flags) and switch between named sets like Home or " +
                                "Untrusted Wi-Fi.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                        SecureButton(
                            onClick = { if (!busy) showSaveDialog = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Save current as…") }
                    }
                }

                if (profiles.isEmpty()) {
                    item {
                        Text(
                            "No saved profiles yet.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    items(profiles, key = { "profile-${it.name}" }) { profile ->
                        ProfileRow(
                            profile = profile,
                            enabled = !busy,
                            onApply = {
                                if (busy) return@ProfileRow
                                busy = true
                                scope.launch {
                                    val screenOn = ScreenPolicyMonitor.isScreenOn(ctx)
                                    val r = manager.applyProfile(profile, installedPkgs, screenOn)
                                    lockdown = manager.isLockdown()
                                    screenOff = PolicyStore.getScreenOffPackages(ctx)
                                    background = PolicyStore.getBackgroundPackages(ctx)
                                    ScreenPolicyMonitor.refresh(ctx)
                                    status = "Applied \"${profile.name}\": ${r.changed} changed" +
                                        if (r.failed > 0) ", ${r.failed} failed" else ""
                                    busy = false
                                }
                            },
                            onDelete = {
                                if (busy) return@ProfileRow
                                PolicyStore.deleteProfile(ctx, profile.name)
                                profiles = PolicyStore.getProfiles(ctx)
                                status = "Deleted \"${profile.name}\""
                            },
                        )
                    }
                }

                // --- Per-app conditional flags ---
                item {
                    SuiteCard {
                        Text(
                            "Block when screen off",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                        BoundaryText(
                            "Cut these apps off the network while the screen is off. " +
                                "\"Background\" is approximated by screen-off — there is no " +
                                "precise per-app foreground signal without heavier permission."
                        )
                    }
                }

                item {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        label = { Text("Search apps") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if (apps.isEmpty()) {
                    item {
                        Text(
                            "Loading installed apps…",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                } else if (filtered.isEmpty()) {
                    item { EmptyState(title = "No matches for \"$query\".") }
                } else {
                    items(filtered, key = { "flag-${it.packageName}" }) { entry ->
                        val isExempt = entry.packageName in exempt
                        ConditionalFlagRow(
                            entry = entry,
                            isExempt = isExempt,
                            screenOffOn = entry.packageName in screenOff,
                            backgroundOn = entry.packageName in background,
                            enabled = !busy,
                            onToggleScreenOff = { want ->
                                PolicyStore.applyScreenOff(ctx, entry.packageName, want)
                                screenOff = PolicyStore.getScreenOffPackages(ctx)
                                ScreenPolicyMonitor.refresh(ctx)
                            },
                            onToggleBackground = { want ->
                                PolicyStore.applyBackground(ctx, entry.packageName, want)
                                background = PolicyStore.getBackgroundPackages(ctx)
                                ScreenPolicyMonitor.refresh(ctx)
                            },
                        )
                    }
                }

                item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
            }
        }
    }

    if (showSaveDialog) {
        SaveProfileDialog(
            onDismiss = { showSaveDialog = false },
            onSave = { name ->
                showSaveDialog = false
                val profile = PolicyStore.snapshotCurrent(ctx, name).copy(
                    allow = manager.allowedPackages(),
                )
                PolicyStore.saveProfile(ctx, profile)
                profiles = PolicyStore.getProfiles(ctx)
                status = "Saved \"$name\""
            },
        )
    }
}

/** One saved-profile row: name + a summary + Apply / Delete. */
@Composable
private fun ProfileRow(
    profile: PolicyProfile,
    enabled: Boolean,
    onApply: () -> Unit,
    onDelete: () -> Unit,
) {
    val mode = if (profile.defaultPolicy == DefaultPolicy.BLOCK_ALL) "Lockdown" else "Allow-by-default"
    SuiteListRow(
        headline = profile.name,
        supporting = "$mode · ${profile.blocked.size} blocked · ${profile.screenOff.size} screen-off",
        trailing = {
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                SecureButton(onClick = onApply, enabled = enabled) { Text("Apply") }
                SecureOutlinedButton(onClick = onDelete, enabled = enabled) { Text("Delete") }
            }
        },
    )
}

/**
 * One installed-app row with two conditional-block switches. Exempt apps render
 * with disabled switches and a protected line — a VPN provider can't be scheduled
 * off the network either.
 */
@Composable
private fun ConditionalFlagRow(
    entry: AppEntry,
    isExempt: Boolean,
    screenOffOn: Boolean,
    backgroundOn: Boolean,
    enabled: Boolean,
    onToggleScreenOff: (Boolean) -> Unit,
    onToggleBackground: (Boolean) -> Unit,
) {
    Column {
        SuiteListRow(
            headline = entry.label,
            supporting = if (isExempt) {
                "Protected — VPN provider / system. Cannot be scheduled off."
            } else {
                entry.packageName
            },
            trailing = {
                Switch(
                    checked = screenOffOn && !isExempt,
                    onCheckedChange = if (isExempt) null else { c -> onToggleScreenOff(c) },
                    enabled = enabled && !isExempt,
                    modifier = Modifier.semantics { role = Role.Switch },
                )
            },
        )
        if (!isExempt) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = UnderstoryTheme.spacing.lg),
                horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            ) {
                SwitchRow(
                    label = "Also block in background",
                    checked = backgroundOn,
                    enabled = enabled,
                    onCheckedChange = onToggleBackground,
                )
            }
        }
    }
}

/** Name prompt for "save current as…". */
@Composable
private fun SaveProfileDialog(
    onDismiss: () -> Unit,
    onSave: (String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Save profile") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Profile name (e.g. Untrusted Wi-Fi)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onSave(name.trim()) },
                enabled = name.trim().isNotEmpty(),
            ) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
