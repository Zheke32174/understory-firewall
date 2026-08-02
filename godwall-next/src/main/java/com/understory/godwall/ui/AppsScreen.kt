package com.understory.godwall.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import androidx.compose.runtime.rememberCoroutineScope
import com.understory.godwall.apps.DeniedApps
import com.understory.godwall.apps.NetworkChainBackend
import com.understory.godwall.apps.UidExemptions
import com.understory.godwall.core.AppPolicy
import com.understory.security.SecureButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.LoadingState
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Per-app policy: blackhole (deny this app's name lookups) and bypass (exclude it from the tun).
 *
 * Both switches say what they actually do in their supporting line. "Block" on its own would be
 * a claim Godwall cannot honour rootlessly — an app denied at DNS can still reach a hardcoded
 * IP — and overstating a security control is worse than not shipping it.
 */
@Composable
fun AppsScreen(padding: PaddingValues) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val chain = remember { NetworkChainBackend(ctx.applicationContext) }
    var query by remember { mutableStateOf("") }
    var applyNote by remember { mutableStateOf("") }
    // Bumped after every toggle so the list re-reads from prefs and the row reflects storage,
    // not a local copy that could drift from it.
    var revision by remember { mutableStateOf(0) }

    val entries by produceState<List<AppPolicy.Entry>?>(initialValue = null, revision) {
        value = withContext(Bg.io) { AppPolicy.installed(ctx) }
    }
    // Read once per revision rather than per row: exemption classification hits the
    // PackageManager, and doing it inside a LazyColumn item would run it on the
    // composition thread for every scroll.
    val denied by produceState(initialValue = emptySet<String>(), revision) {
        value = withContext(Bg.io) { DeniedApps.all(ctx) }
    }
    val exempt by produceState(initialValue = emptySet<String>(), revision) {
        value = withContext(Bg.io) {
            AppPolicy.installed(ctx).map { it.packageName }
                .filter { UidExemptions.isExempt(ctx, it) }.toSet()
        }
    }
    val denyBlocker by produceState<String?>(initialValue = "", revision) {
        value = withContext(Bg.io) { chain.unavailableReason(ctx) }
    }

    val list = entries
    if (list == null) {
        LoadingState(modifier = Modifier.fillMaxSize())
        return
    }

    val filtered = remember(list, query) {
        if (query.isBlank()) list
        else list.filter {
            it.label.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
        }
    }

    LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
        item {
            SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
                Text(
                    text = stringResource(R.string.apps_explainer),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (applyNote.isNotBlank()) {
                    Text(
                        text = applyNote,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                // The platform chain does not survive a reboot, so re-applying has to be
                // something the user can actually ask for rather than an invisible hope.
                SecureButton(
                    enabled = denyBlocker == null,
                    onClick = {
                        scope.launch {
                            applyNote = withContext(Bg.io) {
                                chain.applyAll(DeniedApps.effective(ctx)).note
                            }
                            revision++
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.apps_apply_denials))
                }
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                label = { Text(stringResource(R.string.apps_search)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = UnderstoryTheme.spacing.lg),
            )
            SuiteSectionHeader(stringResource(R.string.apps_count, filtered.size))
        }
        items(filtered, key = { it.packageName }) { app ->
            Column(Modifier.fillMaxWidth()) {
                Text(
                    text = app.label + if (app.system) " " + stringResource(R.string.apps_system_tag) else "",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(
                        start = UnderstoryTheme.spacing.lg,
                        top = UnderstoryTheme.spacing.md,
                        end = UnderstoryTheme.spacing.lg,
                    ),
                )
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg),
                )
                SwitchRow(
                    label = stringResource(R.string.apps_blackhole),
                    supporting = stringResource(R.string.apps_blackhole_help),
                    checked = app.blackholed,
                    onCheckedChange = {
                        AppPolicy.setBlackholed(ctx, app.packageName, it)
                        revision++
                    },
                )
                SwitchRow(
                    label = stringResource(R.string.apps_bypass),
                    supporting = stringResource(R.string.apps_bypass_help),
                    checked = app.bypassed,
                    onCheckedChange = {
                        AppPolicy.setBypassed(ctx, app.packageName, it)
                        revision++
                    },
                )
                // The privileged tier. Disabled with the real reason rather than hidden,
                // and refused outright for packages the exemption gate protects — a
                // firewall that can cut its own VPN provider or the platform's
                // networking stack is a device outage waiting to happen.
                val protectedRow = app.packageName in exempt
                SwitchRow(
                    label = if (denyBlocker == null) stringResource(R.string.apps_deny)
                    else stringResource(R.string.apps_deny_unavailable),
                    supporting = when {
                        protectedRow -> stringResource(
                            R.string.apps_protected,
                            UidExemptions.reason(ctx, app.packageName),
                        )
                        denyBlocker != null -> denyBlocker.orEmpty()
                        else -> stringResource(R.string.apps_deny_help)
                    },
                    enabled = denyBlocker == null && !protectedRow,
                    checked = app.packageName in denied,
                    onCheckedChange = {
                        DeniedApps.set(ctx, app.packageName, it)
                        scope.launch {
                            applyNote = withContext(Bg.io) {
                                chain.applyAll(DeniedApps.effective(ctx)).note
                            }
                            revision++
                        }
                    },
                )
            }
        }
    }
}
