package com.understory.godwall.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
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
import com.understory.godwall.dns.DnsEventLog
import com.understory.security.Clipboard
import com.understory.security.SecureButton
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.delay

/**
 * Every DNS query Godwall has seen this session, attributed to the app that made it.
 *
 * The log is in-memory only and says so. Persisting a device-wide record of every name every app
 * resolved would create exactly the surveillance artefact this suite exists to reduce — so it
 * lives for the session and goes when the process does. Export is a deliberate user action.
 */
@Composable
fun LogScreen(padding: PaddingValues) {
    val ctx = LocalContext.current
    var tick by remember { mutableStateOf(0) }

    // The log is written by the VPN worker thread, so poll rather than subscribe. One second is
    // fast enough to feel live and slow enough to be free.
    LaunchedEffectTick { tick++ }

    val events by produceState(initialValue = emptyList<DnsEventLog.Event>(), tick) {
        value = DnsEventLog.recent()
    }
    val totals = remember(tick) { DnsEventLog.totalQueries() to DnsEventLog.totalBlocked() }
    val perApp = remember(tick) { DnsEventLog.perAppCounts() }

    if (events.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.log_empty_title),
            body = stringResource(R.string.log_empty_body),
            modifier = Modifier.fillMaxSize().padding(padding),
        )
        return
    }

    LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
        item {
            SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
                Text(
                    text = stringResource(R.string.log_totals, totals.first, totals.second),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = stringResource(R.string.log_session_only),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(modifier = Modifier.padding(top = UnderstoryTheme.spacing.sm)) {
                    SecureButton(
                        onClick = {
                            // A resolved-domain list is a privacy artefact, not a password, so
                            // it is copied WITHOUT an auto-clear timer — the user chose to
                            // export it and yanking it out of the clipboard mid-paste would
                            // just lose their data. It still goes through copySensitive so the
                            // clip carries the sensitive flag and stays out of clipboard
                            // history previews.
                            Clipboard.copySensitive(
                                context = ctx,
                                text = DnsEventLog.exportText(),
                                autoClearSeconds = null,
                                label = "godwall-dns-log",
                            )
                        },
                        modifier = Modifier.weight(1f),
                    ) { Text(stringResource(R.string.log_export)) }
                    SecureButton(
                        onClick = { DnsEventLog.clear(); tick++ },
                        modifier = Modifier.weight(1f),
                    ) { Text(stringResource(R.string.log_clear)) }
                }
            }
        }
        if (perApp.isNotEmpty()) {
            item { SuiteSectionHeader(stringResource(R.string.log_by_app)) }
            items(perApp, key = { it.label }) { row ->
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(
                            horizontal = UnderstoryTheme.spacing.lg,
                            vertical = UnderstoryTheme.spacing.xs,
                        ),
                ) {
                    Text(
                        text = row.label,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.log_app_counts, row.queries, row.blocked),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        item { SuiteSectionHeader(stringResource(R.string.log_recent)) }
        items(events) { ev ->
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(
                        horizontal = UnderstoryTheme.spacing.lg,
                        vertical = UnderstoryTheme.spacing.xs,
                    ),
            ) {
                Text(
                    text = ev.domain,
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (ev.blocked) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = if (ev.blocked) {
                        stringResource(R.string.log_row_blocked, ev.appLabel)
                    } else {
                        stringResource(R.string.log_row_allowed, ev.appLabel)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** One-second repeating tick, isolated so the screen body stays readable. */
@Composable
private fun LaunchedEffectTick(onTick: () -> Unit) {
    androidx.compose.runtime.LaunchedEffect(Unit) {
        while (true) {
            delay(1_000)
            onTick()
        }
    }
}
