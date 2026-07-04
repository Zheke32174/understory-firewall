package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import com.understory.net.engine.RebindClassifier
import com.understory.security.SecureButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * DNS-rebinding audit — a rootless, on-demand companion auditor that ALWAYS
 * works (design-v2/firewall.md: companion-first). Enter a hostname, tap to
 * resolve it OFF the main thread, and classify the answers with
 * [RebindClassifier]: a *public* name that resolves to a *private/reserved*
 * address is a rebinding signal.
 *
 * Honest boundary (SuiteCard at the bottom): this only inspects one lookup on
 * demand. System-wide *blocking* of rebinding answers is engine-only — the
 * opt-in Standalone engine ([FirewallRoute.StandaloneHub] via [onOpenEngine]).
 * This screen never starts a VPN and never claims to block anything.
 */
@Composable
fun RebindAuditScreen(onBack: () -> Unit, onOpenEngine: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var host by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<RebindResult?>(null) }
    var checking by remember { mutableStateOf(false) }

    var resolverState by remember { mutableStateOf<ResolverState?>(null) }
    var resolverChecking by remember { mutableStateOf(false) }

    fun runCheck() {
        val h = host.trim()
        if (h.isEmpty()) {
            result = RebindResult.EmptyHost
            return
        }
        checking = true
        result = null
        scope.launch {
            result = withContext(Dispatchers.IO) { resolveAndClassify(h) }
            checking = false
        }
    }

    SuiteScaffold(
        title = stringResource(R.string.rebind_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                stringResource(R.string.rebind_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text(stringResource(R.string.rebind_host_label)) },
                placeholder = { Text(stringResource(R.string.rebind_host_hint)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    imeAction = ImeAction.Go,
                ),
                keyboardActions = KeyboardActions(onGo = { runCheck() }),
                modifier = Modifier.fillMaxWidth(),
            )

            SecureButton(
                onClick = { runCheck() },
                enabled = !checking,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (checking) stringResource(R.string.rebind_resolving)
                    else stringResource(R.string.rebind_resolve_button)
                )
            }

            result?.let { VerdictCard(it) }

            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

            // "Check my resolver" — resolve public canaries and confirm they
            // don't come back reserved (a lying resolver signal).
            SuiteCard {
                Text(
                    stringResource(R.string.rebind_resolver_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    stringResource(R.string.rebind_resolver_detail),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SecureButton(
                    onClick = {
                        resolverChecking = true
                        resolverState = null
                        scope.launch {
                            resolverState = withContext(Dispatchers.IO) { checkResolver() }
                            resolverChecking = false
                        }
                    },
                    enabled = !resolverChecking,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (resolverChecking) stringResource(R.string.rebind_resolver_checking)
                        else stringResource(R.string.rebind_resolver_button)
                    )
                }
                resolverState?.let { s ->
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    val (text, tint) = when (s) {
                        ResolverState.Ok ->
                            stringResource(R.string.rebind_resolver_ok) to UnderstoryTheme.semantic.success
                        ResolverState.Lying ->
                            stringResource(R.string.rebind_resolver_lying) to UnderstoryTheme.semantic.warning
                        ResolverState.Unreachable ->
                            stringResource(R.string.rebind_resolver_unreachable) to MaterialTheme.colorScheme.onSurfaceVariant
                    }
                    Text(text, style = MaterialTheme.typography.bodyMedium, color = tint)
                }
            }

            // Honest boundary: blocking is engine-only. Routes to StandaloneHub.
            SuiteCard(onClick = onOpenEngine) {
                Text(
                    stringResource(R.string.rebind_engine_note_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    stringResource(R.string.rebind_engine_note_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    stringResource(R.string.rebind_engine_note_open),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }

            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

@Composable
private fun VerdictCard(result: RebindResult) {
    val (icon, tint, headline) = when (result) {
        is RebindResult.Risk -> Triple(
            Icons.Filled.Warning,
            UnderstoryTheme.semantic.warning,
            stringResource(R.string.rebind_verdict_risk),
        )
        is RebindResult.Safe -> Triple(
            Icons.Filled.CheckCircle,
            UnderstoryTheme.semantic.success,
            stringResource(R.string.rebind_verdict_safe),
        )
        is RebindResult.Local -> Triple(
            Icons.Filled.Info,
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.rebind_verdict_local),
        )
        is RebindResult.NoAddresses,
        is RebindResult.ResolveFailed,
        RebindResult.EmptyHost -> Triple(
            Icons.Filled.Info,
            MaterialTheme.colorScheme.onSurfaceVariant,
            stringResource(R.string.rebind_verdict_safe),
        )
    }

    SuiteCard {
        HeadlineRow(icon = icon, tint = tint, text = headline, showHeadline = result.showsHeadline)
        when (result) {
            is RebindResult.Risk -> {
                for (reason in result.reasons) {
                    Text(
                        "• $reason",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
                ResolvedIps(result.ips)
            }
            is RebindResult.Safe -> {
                Text(
                    stringResource(R.string.rebind_safe_detail),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ResolvedIps(result.ips)
            }
            is RebindResult.Local -> {
                Text(
                    stringResource(R.string.rebind_local_detail),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ResolvedIps(result.ips)
            }
            is RebindResult.NoAddresses -> Text(
                stringResource(R.string.rebind_no_ips),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            is RebindResult.ResolveFailed -> Text(
                stringResource(R.string.rebind_resolve_failed),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
            RebindResult.EmptyHost -> Text(
                stringResource(R.string.rebind_empty_host),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

@Composable
private fun HeadlineRow(icon: ImageVector, tint: androidx.compose.ui.graphics.Color, text: String, showHeadline: Boolean) {
    if (!showHeadline) return
    androidx.compose.foundation.layout.Row(
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.padding(end = UnderstoryTheme.spacing.sm),
        )
        Text(text, style = MaterialTheme.typography.titleMedium, color = tint)
    }
    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
}

@Composable
private fun ResolvedIps(ips: List<String>) {
    if (ips.isEmpty()) return
    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
    Text(
        stringResource(R.string.rebind_resolved_ips),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    for (ip in ips) {
        Text(ip, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}

// ---------------------------------------------------------------------------
// Off-main-thread work + result model.
// ---------------------------------------------------------------------------

/** UI result of a single rebinding check. */
private sealed interface RebindResult {
    /** Whether the card shows a leading headline row (verdict). */
    val showsHeadline: Boolean

    data class Risk(val reasons: List<String>, val ips: List<String>) : RebindResult {
        override val showsHeadline: Boolean = true
    }
    data class Safe(val ips: List<String>) : RebindResult {
        override val showsHeadline: Boolean = true
    }
    data class Local(val ips: List<String>) : RebindResult {
        override val showsHeadline: Boolean = true
    }
    data object NoAddresses : RebindResult {
        override val showsHeadline: Boolean = false
    }
    data class ResolveFailed(val message: String) : RebindResult {
        override val showsHeadline: Boolean = false
    }
    data object EmptyHost : RebindResult {
        override val showsHeadline: Boolean = false
    }
}

/**
 * Resolve [host] on the current (IO) thread and classify it. MUST be called off
 * the main thread — [InetAddress.getAllByName] does blocking network I/O.
 */
private fun resolveAndClassify(host: String): RebindResult {
    val answers: Array<InetAddress> = try {
        InetAddress.getAllByName(host)
    } catch (t: Throwable) {
        return RebindResult.ResolveFailed(t.message ?: t.javaClass.simpleName)
    }
    val ipStrings = answers.mapNotNull { it.hostAddress }
    if (answers.isEmpty()) return RebindResult.NoAddresses

    if (RebindClassifier.isLocalName(host)) {
        return RebindResult.Local(ipStrings)
    }
    val verdict = RebindClassifier.classify(host, answers.toList())
    return if (verdict.rebindRisk) {
        RebindResult.Risk(reasons = verdict.reasons, ips = ipStrings)
    } else {
        RebindResult.Safe(ipStrings)
    }
}

/** Resolver honesty check state. */
private enum class ResolverState { Ok, Lying, Unreachable }

/**
 * Resolve a couple of well-known PUBLIC canary hostnames and confirm none come
 * back reserved. If every canary fails to resolve → Unreachable; if any
 * resolves to a reserved address → Lying; otherwise Ok. Blocking — IO thread.
 */
private fun checkResolver(): ResolverState {
    var reachedAny = false
    for (canary in RESOLVER_CANARIES) {
        val answers = try {
            InetAddress.getAllByName(canary)
        } catch (_: Throwable) {
            continue
        }
        if (answers.isEmpty()) continue
        reachedAny = true
        val verdict = RebindClassifier.classify(canary, answers.toList())
        if (verdict.rebindRisk) return ResolverState.Lying
    }
    return if (reachedAny) ResolverState.Ok else ResolverState.Unreachable
}

/**
 * Public canary names that must resolve to public addresses through an honest
 * resolver. These are stable, widely-hosted names; a private/reserved answer
 * for any of them is a strong lying-resolver signal.
 */
private val RESOLVER_CANARIES = listOf("example.com", "dns.google", "cloudflare.com")
