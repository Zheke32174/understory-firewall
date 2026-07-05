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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Stage-1 slot-free per-app firewall UI (design-v2/firewall.md §7). Lists
 * installed apps with a per-app block/allow switch driven through [BackendManager],
 * which enforces the [UidExemptions] safety gate. Exempt apps (Tailscale, system)
 * render greyed as "Protected — VPN provider" with a disabled switch, so the UI
 * can NEVER offer to cut the tunnel.
 *
 * HONESTY: the header states plainly that this blocks apps on every network
 * WITHOUT the VPN slot, and that a routing tunnel (Tor / DNS adblock) still needs
 * the VPN slot or root. This surface is POLICY (may an app reach the network),
 * not a tunnel — no comment or copy here claims otherwise.
 *
 * When Shizuku isn't granted, the whole surface degrades to an explainer that
 * points at the Elevation screen — never a dead switch.
 */
@Composable
fun PolicyFirewallScreen(
    onBack: () -> Unit,
    onOpenElevation: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val manager = remember { BackendManager.get(ctx) }

    var available by remember { mutableStateOf(manager.isAvailable()) }
    var tierLabel by remember { mutableStateOf(manager.tierLabel()) }
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var exempt by remember { mutableStateOf<Set<String>>(emptySet()) }
    var blocked by remember { mutableStateOf(manager.blockedPackages()) }
    var query by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        available = manager.isAvailable()
        tierLabel = manager.tierLabel()
        apps = withContext(Dispatchers.IO) { AppListLoader.load(ctx) }
        exempt = withContext(Dispatchers.IO) { UidExemptions.exemptPackages(ctx) }
        blocked = manager.blockedPackages()
    }

    val filtered = remember(apps, query) {
        val q = query.trim().lowercase()
        val base = if (q.isEmpty()) apps else apps.filter {
            it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
        }
        base.sortedBy { it.label.lowercase() }
    }

    SuiteScaffold(title = "App firewall (slot-free)", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

            // Header: active backend + tier label + slot-free badge + honest caveat.
            SuiteCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                ) {
                    Text(
                        text = manager.activeBackend?.name ?: "No backend",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                    SlotFreeBadge()
                }
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    text = tierLabel,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                BoundaryText(
                    "Blocks apps on every network without the VPN slot. A routing " +
                        "tunnel (Tor / DNS adblock) still needs the VPN slot or root."
                )
            }

            if (!available) {
                // Honest degraded state — Tier-1 needs Shizuku.
                SuiteCard {
                    Text(
                        "Needs Shizuku",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    Text(
                        "The slot-free app firewall runs its block through the Shizuku " +
                            "shell (uid 2000). Install Shizuku and grant this app to turn " +
                            "it on. Nothing here uses the VPN slot.",
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

            // Block all / Allow all default toggle.
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                SecureButton(
                    onClick = {
                        if (busy) return@SecureButton
                        busy = true
                        scope.launch {
                            // "Block all" = every non-exempt installed app. Exempt
                            // apps are filtered at the manager choke point too.
                            val desired = apps.map { it.packageName }
                                .filterNot { it in exempt }.toSet()
                            val r = manager.applyAll(desired)
                            blocked = manager.blockedPackages()
                            status = "Block all: ${desired.size} apps, ${r.changed} changed" +
                                if (r.failed > 0) ", ${r.failed} failed" else ""
                            busy = false
                        }
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Block all") }
                SecureOutlinedButton(
                    onClick = {
                        if (busy) return@SecureOutlinedButton
                        busy = true
                        scope.launch {
                            manager.clearAll()
                            blocked = manager.blockedPackages()
                            status = "Allow all: policies cleared"
                            busy = false
                        }
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Allow all") }
            }

            status?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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
                EmptyState(title = "No matches for \"$query\".")
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    items(filtered, key = { "p-${it.packageName}" }) { entry ->
                        val isExempt = entry.packageName in exempt
                        val isBlocked = entry.packageName in blocked
                        AppPolicyRow(
                            entry = entry,
                            isExempt = isExempt,
                            isBlocked = isBlocked,
                            enabled = !busy,
                            onToggle = { wantBlock ->
                                if (busy) return@AppPolicyRow
                                busy = true
                                scope.launch {
                                    val outcome = manager.setBlocked(entry.packageName, wantBlock)
                                    blocked = manager.blockedPackages()
                                    status = renderOutcome(entry.label, outcome)
                                    busy = false
                                }
                            },
                        )
                    }
                    item { Spacer(Modifier.height(UnderstoryTheme.spacing.lg)) }
                }
            }
        }
    }
}

/** Small "slot-free" pill so the surface visibly asserts it never takes the VPN slot. */
@Composable
private fun SlotFreeBadge() {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            text = "SLOT-FREE",
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.sm,
                vertical = UnderstoryTheme.spacing.xs,
            ),
        )
    }
}

/**
 * One installed-app row. Exempt apps render greyed with a "Protected — VPN
 * provider" supporting line and a disabled switch; nobody can toggle Tailscale off
 * the network from here.
 */
@Composable
private fun AppPolicyRow(
    entry: AppEntry,
    isExempt: Boolean,
    isBlocked: Boolean,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    val supporting = when {
        isExempt -> "Protected — VPN provider / system. Cannot be blocked."
        isBlocked -> "${entry.packageName}  ·  blocked on all networks"
        else -> entry.packageName
    }
    SuiteListRow(
        headline = entry.label,
        supporting = supporting,
        trailing = {
            Switch(
                checked = isBlocked && !isExempt,
                onCheckedChange = if (isExempt) null else { checked -> onToggle(checked) },
                enabled = enabled && !isExempt,
                modifier = Modifier.semantics { role = Role.Switch },
            )
        },
    )
}

private fun renderOutcome(label: String, outcome: BackendManager.SetBlockedOutcome): String =
    when (outcome) {
        BackendManager.SetBlockedOutcome.APPLIED -> "$label: policy applied"
        BackendManager.SetBlockedOutcome.UNCHANGED -> "$label: no change"
        BackendManager.SetBlockedOutcome.PROTECTED -> "$label is protected — cannot be blocked"
        BackendManager.SetBlockedOutcome.UNAVAILABLE -> "No slot-free backend available"
        BackendManager.SetBlockedOutcome.FAILED -> "$label: command failed"
    }
