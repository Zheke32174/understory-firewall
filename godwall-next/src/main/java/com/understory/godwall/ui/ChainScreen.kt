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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import androidx.compose.runtime.rememberCoroutineScope
import com.understory.godwall.chain.ChainDialer
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.chain.ProxyHop
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
 * The egress chain: an ordered list of proxy hops the resolver's traffic is routed through.
 *
 * Order is the whole meaning of a chain, so hops are shown numbered and reorderable rather than
 * as an unordered set. The chain fails **closed** — if a hop cannot be reached, the query is not
 * quietly sent direct, because a chain that silently degrades to no chain is precisely the case
 * its user is trying to avoid.
 */
@Composable
fun ChainScreen(padding: PaddingValues) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var revision by remember { mutableStateOf(0) }
    var testResult by remember { mutableStateOf("") }
    var testing by remember { mutableStateOf(false) }

    val enabled = remember(revision) { EndpointChain.isEnabled(ctx) }
    val hops = remember(revision) { EndpointChain.hops(ctx) }

    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var kind by remember { mutableStateOf(HopKind.SOCKS5) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SwitchRow(
            label = stringResource(R.string.chain_enable),
            supporting = stringResource(R.string.chain_enable_help),
            checked = enabled,
            onCheckedChange = {
                EndpointChain.setEnabled(ctx, it)
                revision++
            },
        )

        // Dial the configured chain for real, to the resolver the DNS screen is set to,
        // and print the established path or the exact failure. A chain you have not
        // dialled is a list of strings.
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            SecureButton(
                enabled = !testing && hops.isNotEmpty(),
                onClick = {
                    testing = true
                    testResult = ""
                    scope.launch {
                        testResult = withContext(Bg.io) {
                            val target = com.understory.godwall.dns.DnsSettings.ip(ctx)
                            when (
                                val r = ChainDialer.dial(
                                    service = null,
                                    hops = EndpointChain.hops(ctx),
                                    destHost = target,
                                    destPort = 853,
                                    timeoutMs = 8_000,
                                )
                            ) {
                                is ChainDialer.Result.Connected -> {
                                    runCatching { r.socket.close() }
                                    "Established: ${r.path}"
                                }
                                is ChainDialer.Result.Unavailable -> r.reason
                            }
                        }
                        testing = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.chain_test))
            }
            if (testResult.isNotBlank()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    text = testResult,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        SuiteSectionHeader(stringResource(R.string.chain_hops, hops.size))
        if (hops.isEmpty()) {
            SuiteCard(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
                Text(
                    text = stringResource(R.string.chain_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        hops.forEachIndexed { index, hop ->
            SuiteListRow(
                headline = "${index + 1}. ${hop.label()}",
                supporting = stringResource(R.string.chain_hop_help),
                trailing = {
                    Row {
                        if (index > 0) {
                            SecureButton(onClick = {
                                EndpointChain.move(ctx, index, index - 1)
                                revision++
                            }) { Text(stringResource(R.string.chain_up)) }
                        }
                        SecureButton(onClick = {
                            EndpointChain.remove(ctx, hop.id)
                            revision++
                        }) { Text(stringResource(R.string.chain_remove)) }
                    }
                },
            )
        }

        SuiteSectionHeader(stringResource(R.string.chain_add))
        Row(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            HopKind.entries.forEach { k ->
                FilterChip(
                    selected = kind == k,
                    onClick = { kind = k },
                    label = { Text(k.label) },
                    modifier = Modifier.padding(end = UnderstoryTheme.spacing.sm),
                )
            }
        }
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            singleLine = true,
            label = { Text(stringResource(R.string.chain_host)) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.lg),
        )
        OutlinedTextField(
            value = port,
            onValueChange = { port = it.filter(Char::isDigit) },
            singleLine = true,
            label = { Text(stringResource(R.string.chain_port)) },
            modifier = Modifier.fillMaxWidth().padding(UnderstoryTheme.spacing.lg),
        )
        OutlinedTextField(
            value = user,
            onValueChange = { user = it },
            singleLine = true,
            label = { Text(stringResource(R.string.chain_user)) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.lg),
        )
        OutlinedTextField(
            value = pass,
            onValueChange = { pass = it },
            singleLine = true,
            label = { Text(stringResource(R.string.chain_pass)) },
            modifier = Modifier.fillMaxWidth().padding(UnderstoryTheme.spacing.lg),
        )
        SecureButton(
            enabled = host.isNotBlank() && port.toIntOrNull() != null,
            onClick = {
                val p = port.toIntOrNull() ?: return@SecureButton
                val hop = when (kind) {
                    HopKind.SOCKS5 -> ProxyHop.Socks5(
                        id = EndpointChain.newId(),
                        host = host.trim(),
                        port = p,
                        username = user.trim(),
                        password = pass,
                    )
                    HopKind.HTTP -> ProxyHop.HttpConnect(
                        id = EndpointChain.newId(),
                        host = host.trim(),
                        port = p,
                        username = user.trim(),
                        password = pass,
                    )
                }
                EndpointChain.add(ctx, hop)
                host = ""; port = ""; user = ""; pass = ""
                revision++
            },
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.lg),
        ) { Text(stringResource(R.string.chain_add_hop)) }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}

private enum class HopKind(val label: String) {
    SOCKS5("SOCKS5"),
    HTTP("HTTP CONNECT"),
}
