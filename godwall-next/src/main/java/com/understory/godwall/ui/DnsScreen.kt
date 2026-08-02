package com.understory.godwall.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import com.understory.godwall.dns.BlocklistRepository
import com.understory.godwall.dns.DnsProbe
import com.understory.godwall.dns.DnsSettings
import com.understory.godwall.dns.UpstreamResolver
import com.understory.net.engine.DnsMessage
import com.understory.security.SecureButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The resolver and the filter: upstream transport, blocklist state, custom rules.
 *
 * Presets exist because typing a DoT hostname correctly matters — a typo silently downgrades
 * the connection or breaks resolution entirely, and neither failure is obvious from the UI.
 */
@Composable
fun DnsScreen(padding: PaddingValues, onOpenLog: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var revision by remember { mutableStateOf(0) }
    val mode = remember(revision) { DnsSettings.mode(ctx) }
    var ip by remember(revision) { mutableStateOf(DnsSettings.ip(ctx)) }
    var hostname by remember(revision) { mutableStateOf(DnsSettings.hostname(ctx)) }
    var path by remember(revision) { mutableStateOf(DnsSettings.dohPath(ctx)) }
    var customDomain by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var fetchResult by remember { mutableStateOf("") }
    var probeResult by remember { mutableStateOf("") }
    var probing by remember { mutableStateOf(false) }

    val filterOn = remember(revision) { BlocklistRepository.isFilterEnabled(ctx) }
    val stats = remember(revision) { BlocklistRepository.stats() }
    val answerStyle = remember(revision) { BlocklistRepository.answerStyle(ctx) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SuiteSectionHeader(stringResource(R.string.dns_upstream))
        SuiteCard(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            Text(
                text = stringResource(R.string.dns_upstream_help),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row {
                UpstreamResolver.Mode.entries.forEach { m ->
                    FilterChip(
                        selected = mode == m,
                        onClick = {
                            DnsSettings.setMode(ctx, m)
                            revision++
                        },
                        label = { Text(m.name) },
                        modifier = Modifier.padding(end = UnderstoryTheme.spacing.sm),
                    )
                }
            }
        }

        OutlinedTextField(
            value = ip,
            onValueChange = { ip = it; DnsSettings.setIp(ctx, it) },
            singleLine = true,
            label = { Text(stringResource(R.string.dns_ip)) },
            modifier = Modifier.fillMaxWidth().padding(UnderstoryTheme.spacing.lg),
        )
        if (mode != UpstreamResolver.Mode.PLAINTEXT) {
            OutlinedTextField(
                value = hostname,
                onValueChange = { hostname = it; DnsSettings.setHostname(ctx, it) },
                singleLine = true,
                label = { Text(stringResource(R.string.dns_hostname)) },
                modifier = Modifier.fillMaxWidth()
                    .padding(horizontal = UnderstoryTheme.spacing.lg),
            )
        }
        if (mode == UpstreamResolver.Mode.DOH) {
            OutlinedTextField(
                value = path,
                onValueChange = { path = it; DnsSettings.setDohPath(ctx, it) },
                singleLine = true,
                label = { Text(stringResource(R.string.dns_path)) },
                modifier = Modifier.fillMaxWidth()
                    .padding(UnderstoryTheme.spacing.lg),
            )
        }

        // "Encrypted DNS is configured" and "encrypted DNS works" are different claims,
        // and only the second is worth showing. This runs a real query through the
        // configured transport and the configured chain, OFF the tunnel, and prints what
        // actually came back — including the failure, which is the case that matters.
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            SecureButton(
                enabled = !probing,
                onClick = {
                    probing = true
                    probeResult = ""
                    scope.launch {
                        val r = withContext(Bg.io) { DnsProbe.run(ctx) }
                        probeResult = r.line
                        probing = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (probing) stringResource(R.string.dns_test_running)
                    else stringResource(R.string.dns_test),
                )
            }
            if (probeResult.isNotBlank()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    text = probeResult,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        SuiteSectionHeader(stringResource(R.string.dns_presets))
        PRESETS.forEach { (label, addr) ->
            SuiteListRow(
                headline = label,
                supporting = "${addr.first} — ${addr.second}",
                onClick = {
                    DnsSettings.applyPreset(ctx, addr.first, addr.second)
                    revision++
                },
            )
        }

        SuiteSectionHeader(stringResource(R.string.dns_filter))
        SwitchRow(
            label = stringResource(R.string.dns_filter_toggle),
            supporting = stringResource(R.string.dns_filter_stats, stats.totalDomains),
            checked = filterOn,
            onCheckedChange = {
                BlocklistRepository.setFilterEnabled(ctx, it)
                revision++
            },
        )
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                text = stringResource(R.string.dns_answer_style),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                text = stringResource(R.string.dns_answer_style_help),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row {
                DnsMessage.BlockAnswer.entries.forEach { style ->
                    FilterChip(
                        selected = answerStyle == style,
                        onClick = {
                            BlocklistRepository.setAnswerStyle(ctx, style)
                            revision++
                        },
                        label = { Text(style.name) },
                        modifier = Modifier.padding(end = UnderstoryTheme.spacing.sm),
                    )
                }
            }
        }

        SuiteSectionHeader(stringResource(R.string.dns_custom))
        OutlinedTextField(
            value = customDomain,
            onValueChange = { customDomain = it },
            singleLine = true,
            label = { Text(stringResource(R.string.dns_custom_domain)) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.lg),
        )
        Row(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            SecureButton(
                onClick = {
                    if (customDomain.isNotBlank()) {
                        BlocklistRepository.addCustomBlock(ctx, customDomain)
                        customDomain = ""
                        scope.launch { withContext(Bg.io) { BlocklistRepository.reload(ctx) } }
                        revision++
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.dns_add_block)) }
            Spacer(Modifier.padding(horizontal = UnderstoryTheme.spacing.xs))
            SecureButton(
                onClick = {
                    if (customDomain.isNotBlank()) {
                        BlocklistRepository.addCustomAllow(ctx, customDomain)
                        customDomain = ""
                        scope.launch { withContext(Bg.io) { BlocklistRepository.reload(ctx) } }
                        revision++
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.dns_add_allow)) }
        }
        BlocklistRepository.customBlock(ctx).forEach { d ->
            SuiteListRow(
                headline = d,
                supporting = stringResource(R.string.dns_custom_blocked),
                onClick = {
                    BlocklistRepository.removeCustomBlock(ctx, d)
                    scope.launch { withContext(Bg.io) { BlocklistRepository.reload(ctx) } }
                    revision++
                },
            )
        }
        BlocklistRepository.customAllow(ctx).forEach { d ->
            SuiteListRow(
                headline = d,
                supporting = stringResource(R.string.dns_custom_allowed),
                onClick = {
                    BlocklistRepository.removeCustomAllow(ctx, d)
                    scope.launch { withContext(Bg.io) { BlocklistRepository.reload(ctx) } }
                    revision++
                },
            )
        }

        SuiteSectionHeader(stringResource(R.string.dns_update))
        SuiteCard(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            Text(
                text = if (fetchResult.isBlank()) stringResource(R.string.dns_update_help)
                else fetchResult,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureButton(
                enabled = !busy,
                onClick = {
                    busy = true
                    scope.launch {
                        // Network + parse, so never on the main thread. The result string is
                        // whatever actually happened, including the failure text.
                        val msg = withContext(Bg.io) { BlocklistRepository.fetchAndCache(ctx) }
                        fetchResult = msg
                        busy = false
                        revision++
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.dns_update_now)) }
        }

        SuiteListRow(
            headline = stringResource(R.string.title_log),
            supporting = stringResource(R.string.dns_open_log),
            onClick = onOpenLog,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}

/**
 * Known-good encrypted resolvers, as (ip, hostname). Typing these by hand is error-prone and a
 * wrong hostname fails in a way the UI cannot distinguish from a network problem.
 */
private val PRESETS: List<Pair<String, Pair<String, String>>> = listOf(
    "Cloudflare" to ("1.1.1.1" to "cloudflare-dns.com"),
    "Quad9 (filtered)" to ("9.9.9.9" to "dns.quad9.net"),
    "Mullvad (no logs)" to ("194.242.2.2" to "dns.mullvad.net"),
    "AdGuard (filtering)" to ("94.140.14.14" to "dns.adguard-dns.com"),
)
